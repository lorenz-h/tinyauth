import base64
import datetime
import json
import secrets
from typing import Optional, Tuple
import argparse

from aiohttp import web
import logging

from cryptography.fernet import Fernet
from tinydb import TinyDB, Query
from pathlib import Path
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware


AUTH_COOKIE_NAME = "authToken"
AUTH_COOKIE_SALT_LENGTH = 32


class PermissionLevels:
    ADMIN = 100
    USER = 20
    STRANGER = 0


class AuthenticationException(Exception):
    pass


class TinyAuthServer(web.Application):
    def __init__(self, data_dir: Path, constant_secret: str, admin_password: str, user_cache_size: int):
        super().__init__()
        self.data_dir = data_dir
        self.data_dir.mkdir(exist_ok=True, parents=False)
        self.db = TinyDB(data_dir / "db.json", indent=4, storage=CachingMiddleware(JSONStorage))
        self.users = self.db.table('users', cache_size=user_cache_size)
        self.setup_root_user(admin_password)
        self.encryptor = Fernet(self.load_fernet_key())
        self.constant_secret: str = constant_secret

        self.add_routes([
            web.post('/auth/get_cookie', self.handle_get_cookie),
            web.get('/auth', self.handle_is_authenticated),
            web.get('/auth/login', self.handle_login_form),
            web.post('/auth/logout', self.handle_logout)])

    def __enter__(self):
        self.db.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    async def handle_logout(request: web.Request):
        cookie = request.cookies.get(AUTH_COOKIE_NAME)
        if cookie == "":
            return web.Response(reason="Not logged in", status=400)
        else:
            response = web.Response(reason=f"Successfully logged out.", status=200)
            response.set_cookie(AUTH_COOKIE_NAME, "")
            return response

    def setup_root_user(self, admin_password: str):
        user = Query()
        element = self.users.get(user.name == 'admin')
        if element is None:
            self.logger.info("Recreating database.")
            self.users.insert({'name': 'admin', 'password': admin_password, "permissions": PermissionLevels.ADMIN})
        self.users.update({'password': admin_password}, user.name == 'admin')

    async def handle_is_authenticated(self, request: web.Request) -> web.Response:
        cookie = request.cookies.get(AUTH_COOKIE_NAME)
        try:
            user_name = await self.unpack_encrypted_cookie(cookie)
            user = self.users.get(Query().name == user_name)
            if user is None:
                return web.Response(reason="User not found.", status=401)
            else:
                self.logger.info(user)
                return web.Response(reason="Authenticated", status=200)
        except AuthenticationException:
            self.logger.info("Could not authenticate.")
            return web.Response(reason="Could not authenticate.", status=401)

    @staticmethod
    async def handle_login_form(request: web.Request):
        return web.FileResponse(Path(__file__).parent.parent / "resources" / 'login.html')

    async def handle_get_cookie(self, request: web.Request):
        login_info = await request.post()

        query = Query()

        user = login_info.get("user", None)
        if user is None:
            self.logger.info("get cookie failed, because json posted did not contain user")
            return web.Response(reason=f"You must specify the user to login", status=400)
        if self.users.get(query.name == user) is None:
            self.logger.info(f"get cookie failed, unknown user {user}")
            return web.Response(reason=f"Invalid login credentials", status=400)

        password = login_info.get("password", None)
        if password is None:
            self.logger.info("get cookie failed, because json posted did not contain password")
            return web.Response(reason=f"You must specify a password", status=400)
        if password != self.users.get(query.name == user)["password"]:
            self.logger.info("Get cookie failed, invalid password.")
            return web.Response(reason=f"Invalid login credentials", status=400)
        self.logger.info(f"Succesfully authenticated user {user}")
        response = web.json_response(data={"authenticated": "true"}, reason="Successfully authenticated.")
        cookie: str = await self.create_encrypted_cookie(user)
        response.set_cookie(AUTH_COOKIE_NAME, cookie, secure=True, httponly=True)
        response.content_type = "application/json"
        return response

    async def create_encrypted_cookie(self, user: str) -> str:
        cookie_salt = secrets.token_hex(AUTH_COOKIE_SALT_LENGTH)
        # we use the auth cookie constant secret to quickly check if a cookie is valid after decryption.
        valid_until = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=60)
        valid_until_iso = valid_until.isoformat(timespec="seconds")

        raw_cookie = "@@@@".join([self.constant_secret, user, valid_until_iso, cookie_salt]).encode("utf-8")
        encrypted_cookie = self.encryptor.encrypt(raw_cookie)
        return base64.b64encode(encrypted_cookie).decode("utf-8")

    async def unpack_encrypted_cookie(self, cookie: str) -> str:
        if cookie is None:
            raise AuthenticationException("Could not find authentication cookie.")
        try:
            # returns str to indicate the user, raises AuthenticationException otherwise
            encrypted_cookie = base64.b64decode(cookie.encode("utf-8"))
            raw_cookie = self.encryptor.decrypt(encrypted_cookie).decode("utf-8")
            constant_secret, user, valid_until_iso, _ = raw_cookie.split("@@@@")
            if constant_secret != self.constant_secret:
                raise AuthenticationException("Constant secret does not match.")
            if datetime.datetime.fromisoformat(valid_until_iso) < datetime.datetime.now(tz=datetime.timezone.utc):
                raise AuthenticationException("Stale authentication cookie.")
            else:
                return user
        except UnicodeDecodeError:
            msg = "Could decode auth cookie."
            self.logger.info(msg)
            raise AuthenticationException(msg)
        except ValueError:
            msg = "Could not unpack authentication cookie."
            self.logger.info(msg)
            raise AuthenticationException(msg)
        except Exception as e:
            msg = "Could not unpack Cookie. Unhandled exception."
            self.logger.exception(msg, e)
            raise AuthenticationException(msg)

    def load_fernet_key(self) -> bytes:
        keypath = self.data_dir / "fernet.key"
        if not keypath.exists():
            new_key = Fernet.generate_key()
            with open(keypath, "wb") as fp:
                fp.write(new_key)
            return new_key
        else:
            with open(keypath, "rb") as fp:
                return fp.read()


def run_server():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", default=8334, type=int, required=False)
    parser.add_argument("--host", default="127.0.0.1", type=str, required=False)
    parser.add_argument("--admin_password", type=str, required=True, help="Password for the admin user. The admin account can be used to add/remove users.")
    parser.add_argument("--constant_secret", type=str, required=True, help="The constant secret used to verify that a decrypted token is well formed.")
    parser.add_argument("--user_cache_size", type=int, default=30, required=False, help="Maximum Number of users to keep in memory.")
    parser.add_argument("--debug", action="store_true")


    args = parser.parse_args()

    logging_level = logging.DEBUG if args.debug else logging.INFO

    logging.basicConfig(level=logging_level)

    app = TinyAuthServer(
        data_dir=Path(__file__).parent.parent / "tinyauth_data", 
        constant_secret=args.constant_secret,
        admin_password=args.admin_password,
        user_cache_size=args.user_cache_size
        )
    
    with app:
        web.run_app(app,  host=args.host, port=args.port)

