from setuptools import setup

setup(
    name='mango_auth',
    version='0.0.1',
    py_modules=['mango_auth'],
    install_requires=[
        'python_irodsclient',
    ],
    entry_points={
        'console_scripts': [
            'mango_auth = mango_auth:iinit_cli',
        ],
    },
)
