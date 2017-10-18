#!/usr/bin/env python3

# === IMPORTS ===
from setuptools import setup

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===

# === MAIN ===
setup(
    name='inovonics_cloud_oauth',
    version='0.1.0.0',
    description='Classes implementing functionality for flask-oauthlib using Redis as the backing store. ',
    author='Daniel Williams',
    author_email='dwilliams@inovonics.com',
    license='MIT',
    install_requires=[line.strip() for line in open('requirements.txt', 'r')],
    dependency_links=[
        'git+https://github.com/inovonics/cloud-datastore.git#inovonics-cloud-datastore-0.1'
    ],
    packages=['inovonics.cloud.oauth']
)
