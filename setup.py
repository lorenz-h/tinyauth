from setuptools import setup, find_packages
setup(
    name="tinyauth",
    version="0.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': ['tinyauth=tinyauth.server:run_server']
    }
)