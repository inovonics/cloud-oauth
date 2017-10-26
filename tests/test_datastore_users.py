#!/usr/bin/python3

# === IMPORTS ===
import json
import logging
import redpipe
import unittest
import uuid

from parameterized import parameterized
from passlib.hash import pbkdf2_sha512

from inovonics.cloud.oauth.datastore import OAuthUsers, OAuthUser
from inovonics.cloud.datastore import DuplicateException, ExistsException, InvalidDataException, NotExistsException

from helpers import getDStore, custom_name_func

# === GLOBALS ===
logging.basicConfig(level=logging.DEBUG)

default_user_data = [
    #("username", "password", "is_active", "scopes")
    ("admin@example.com", "password", True, ['webapp', 'iwcadmin']),
    ("test1.user@example.com", "test.password.321", True, ['webapp', 'iwcadmin']),
    ("test2.user@example.com", "test.password.654", True, ['webapp', 'iwcadmin']),
    ("test3.user@example.com", "test.password.987", True, ['webapp'])
]

create_user_data = [
    #("username", "password", "is_active", "scopes")
    ("admin1@example.com", "password", True, ['webapp', 'iwcadmin']),
    ("test01.user@example.com", "test.password.321", True, ['webapp', 'iwcadmin']),
    ("test02.user@example.com", "test.password.654", True, ['webapp', 'iwcadmin']),
    ("test03.user@example.com", "test.password.987", True, ['webapp'])
]

create_user_bad_data = [
]

update_user_data = [
    #("username", "update_field", "update_value")
    ("admin@example.com", "password", "newpassword"),
    ("test1.user@example.com", "is_active", False),
    ("test2.user@example.com", "scopes", ['webapp']),
    ("test3.user@example.com", "username", "test4.user@example.com")
]

update_user_bad_data = [
]

remove_user_data = [
]

remove_user_bad_data = [
]

# NOTE: Bulk create, update, remove and reuse non-bulk versions

# === FUNCTIONS ===

# === CLASSES ===
class TestCasesDatastoreUsers(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(type(self).__name__)
        super().__init__(*args, **kwargs)

    def setUp(self):
        self.logger.info("Setting up")
        # Setup the datastore for testing
        self.dstore = getDStore()
        # Flush the database
        self.dstore.redis.flushdb()
        # Load the default user data
        self._load_default_user_data()
        # Instantiate the datastore model class for the test
        self.db_users = OAuthUsers(self.dstore)

    @parameterized.expand(create_user_data, testcase_func_name=custom_name_func)
    def test_create_user(self, username, password, is_active, scopes):
        self.logger.info("Running test_create_user")
        # FIXME: Add the values from the call?
        # Add the user via the datastore create method
        user_data = {
            'username': username,
            'is_active': is_active,
            'scopes': scopes
        }
        user = OAuthUser(user_data)
        user.update_password(password)
        self.db_users.create(user)

        # Verify the correct data via direct calls to redis
        ## Check the user_id from the index
        tmp_user_id = self.dstore.redis.get("oauth:user:{}".format(username)).decode('utf-8')
        self.logger.debug("tmp_user_id: %s", tmp_user_id)
        self.assertEqual(tmp_user_id, user.user_id)

        ## Setup the key for the hash
        tmp_key = "oauth:user{{{}}}".format(tmp_user_id)
        self.logger.debug("tmp_key: %s", tmp_key)

        ## Check the username
        tmp_username = self.dstore.redis.hget(tmp_key, 'username').decode('utf-8')
        self.logger.debug("tmp_username: %s", tmp_username)
        self.assertEqual(tmp_username, username)

        ## Check is_active
        tmp_is_active = self.dstore.redis.hget(tmp_key, 'is_active').decode('utf-8')
        self.logger.debug("tmp_is_active: %s", tmp_is_active)
        self.assertEqual(bool(tmp_is_active), bool(is_active))

        ## Check the scopes
        tmp_scopes = self.dstore.redis.hget(tmp_key, 'scopes').decode('utf-8')
        self.logger.debug("tmp_scopes: %s", tmp_scopes)
        self.assertEqual(json.loads(tmp_scopes), scopes)

        ## Check the password
        tmp_passhash = self.dstore.redis.hget(tmp_key, 'password_hash').decode('utf-8')
        self.logger.debug("tmp_passhash: %s", tmp_passhash)
        self.assertTrue(pbkdf2_sha512.verify(password, tmp_passhash))

        ## Check username is in usernames list
        tmp_user_in_usernames = self.dstore.redis.sismember("oauth:usernames", username)
        self.logger.debug("tmp_user_in_usernames: %s", tmp_user_in_usernames)
        self.assertTrue(tmp_user_in_usernames)

        ## Check user_id is in user_ids list
        tmp_user_in_user_ids = self.dstore.redis.sismember("oauth:user_ids", tmp_user_id)
        self.logger.debug("tmp_user_in_user_ids: %s", tmp_user_in_user_ids)
        self.assertTrue(tmp_user_in_user_ids)

    @parameterized.expand(update_user_data, testcase_func_name=custom_name_func)
    def test_update_user(self, username, update_field, update_value):
        self.logger.info("Running test_update_user")
        # Retrieve the user data
        tmp_user_id = self.dstore.redis.get("oauth:user:{}".format(username)).decode('utf-8')
        self.logger.debug("tmp_user_id: %s", tmp_user_id)
        tmp_user = self.db_users.get_by_id(tmp_user_id)
        
        # Change the values
        if update_field == "password":
            tmp_user.update_password(update_value)
        else:
            tmp_user[update_field] = update_value
        
        # Update the user via the datastore
        self.db_users.update(tmp_user)
        
        # Verify the correct data via direct calls to redis

    def tearDown(self):
        self.logger.info("Tearing down")
        # Flush the database again to be safe
        self.dstore.redis.flushdb()

    def _load_default_user_data(self):
        self.logger.info("Loading the default user set")
        # Load each of the default users
        with redpipe.autoexec() as pipe:
            for user in default_user_data:
                # User data will be loaded via direct calls to Redis
                tmp_user_id = uuid.uuid4()
                tmp_key = "oauth:user{{{}}}".format(tmp_user_id)
                pipe.hset(tmp_key, "user_id", tmp_user_id)
                pipe.hset(tmp_key, "username", user[0])
                pipe.hset(tmp_key, "password_hash", pbkdf2_sha512.hash(user[1]))
                pipe.hset(tmp_key, "is_active", user[2])
                pipe.hset(tmp_key, "scopes", json.dumps(user[3]))
                # Setup the appropriate references
                pipe.set("oauth:user:{}".format(user[0]), tmp_user_id)
                # Load the username and user_id into the appropriate set
                pipe.sadd("oauth:usernames", user[0])
                pipe.sadd("oauth:user_ids", tmp_user_id)

# === MAIN ===
if __name__ == '__main__':
    # THIS SCRIPT SHOULD NEVER BE CALLED DIRECTLY
    # Call from the base directory of the package with the following command:
    # python3 -m unittest tests.<name_of_module>.<name_of_class>
    pass
