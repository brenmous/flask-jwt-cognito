from setuptools import setup, find_packages

setup(
    name='flask-jwt-cognito',
    version='0.1',
    author='Brenainn Moushall',
    author_email='bmoush@gmail.com',
    packages=find_packages(),
    install_requires=[
        'flask',
        'flask-JWT-extended',
        'jwcrypto'
    ]
)
