#!/usr/bin/env python3

# === IMPORTS ===
from setuptools import setup

# === GLOBALS ===

# === FUNCTIONS ===
def get_version():
    version = {}
    with open('inovonics/cloud/oauth/__version__.py') as fp:
        exec(fp.read(), version)
    #print("version: {}".format(version['__version__']))
    return version['__version__']

# === CLASSES ===

# === MAIN ===
setup(
    name='inovonics_cloud_oauth',
    version=get_version(),
    description='Classes implementing functionality for flask-oauthlib using Redis as the backing store.',
    keywords=[],
    author='Daniel Williams',
    author_email='dwilliams@inovonics.com',
    license='MIT',
    install_requires=[line.strip() for line in open('requirements.txt', 'r')],
    packages=['inovonics.cloud.oauth', 'inovonics.cloud.oauth.datastore'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
