from setuptools import setup

setup(
    name='flask-jwt-cognito',
    version='0.1',
    author='Brenainn Moushall',
    author_email='bmoush@gmail.com',
    packages=["flask_jwt_cognito"],
    install_requires=[
        'flask',
        'flask-JWT-extended',
        'jwcrypto'
    ]
)
