#!/usr/bin/python3

# === IMPORTS ===
import os

from inovonics.cloud.datastore import InoRedis

# === GLOBALS ===
dstore = None

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = os.getenv('REDIS_PORT', 6379)
REDIS_DB = os.getenv('REDIS_DB', 0)

# === FUNCTIONS ===
def getDStore():
    global dstore
    if dstore is None:
        dstore = InoRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    return dstore

def custom_name_func(testcase_func, param_num, param):
    return "{}_{}".format(testcase_func.__name__, param_num)

# === CLASSES ===

# === MAIN ===
if __name__ == '__main__':
    pass
