#!/usr/bin/python3

# === IMPORTS ===
import logging
import unittest

from parameterized import parameterized
from passlib.hash import pbkdf2_sha512

from inovonics.cloud.oauth.datastore import OAuthUsers, OAuthUser
from inovonics.cloud.datastore import DuplicateException, ExistsException, InvalidDataException, NotExistsException

from helpers import getDStore

# === GLOBALS ===
logging.basicConfig(level=logging.DEBUG)

create_user_data = [
    #("username", "password", "first_name", "last_name", "is_active", "scopes_list")
    ("admin@example.com", "password", "Admin", "Testuser", True, ['webapp', 'iwcadmin']),
    ("test1.user@example.com", "test.password.321", "Test1", "User", True, ['webapp', 'iwcadmin']),
    ("test2.user@example.com", "test.password.654", "Test2", "User", True, ['webapp', 'iwcadmin']),
    ("test3.user@example.com", "test.password.987", "Test3", "User", True, ['webapp'])
]

update_user_data = [
    #("username", "password", "first_name", "last_name", "is_active", "scopes_list")
    ("admin@example.com", "password", "Admin", "Testuser", True, ['webapp', 'iwcadmin']),
    ("test1.user@example.com", "test.password.321", "Test1", "User", True, ['webapp', 'iwcadmin']),
    ("test2.user@example.com", "test.password.654", "Test2", "User", True, ['webapp', 'iwcadmin']),
    ("test3.user@example.com", "test.password.987", "Test3", "User", True, ['webapp'])
]

remove_user_data = [
]

create_user_bad_data = [
]

update_user_bad_data = [
]

remove_user_bad_data = [
]

# NOTE: Bulk create, update, remove and reuse non-bulk versions

# === FUNCTIONS ===

# === CLASSES ===
class TestCasesUserDatastore(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(type(self).__name__)
        super().__init__(*args, **kwargs)

    def setUp(self):
        self.logger.info("Setting up")
        # Setup the datastore for testing
        self.dstore = getDStore()
        # Flush the database
        self.dstore.redis.flushdb()
        # Instantiate the datastore model class for the test
        self.db_users = OAuthUsers(self.dstore)

    @parameterized.expand(create_user_data)
    def test_create_user(self, username, password, first_name, last_name, is_active, scopes_list):
        self.logger.info("Running test_create_user")
        # FIXME: Add the values from the call?
        # Add the user via the datastore create method
        user_data = {
            'username': username,
            'is_active': is_active,
            'scopes': scopes_list
        }
        user = OAuthUser(user_data)
        user.update_password(password)
        self.db_users.create(user)

        # Verify the correct data via direct calls to redis
        ## Check the user_id from the index
        tmp_user_id = self.dstore.redis.get("user:{}".format(username)).decode('utf-8')
        self.assertEqual(tmp_user_id, user.user_id)
        ## Setup the key for the hash
        tmp_key = "user{{{}}}".format(tmp_user_id)
        ## Check the username
        tmp_username = self.dstore.redis.hget(tmp_key, 'username')
        self.logger.debug("tmp_username: %s", tmp_username)
        tmp_username = tmp_username.decode('utf-8')
        self.assertEqual(tmp_username, username)
        ## Check is_active
        tmp_is_active = self.dstore.redis.hget(tmp_key, 'is_active').decode('utf-8')
        self.assertEqual(tmp_is_active, is_active)
        ## Check the scopes
        tmp_scopes_list = self.dstore.redis.hget(tmp_key, 'scopes').decode('utf-8')
        self.assertEqual(tmp_scopes_list, scopes_list)
        ## Check the password
        tmp_passhash = self.dstore.redis.hget(tmp_key, 'password_hash').decode('utf-8')
        self.assertTrue(pbkdf2_sha512.verify(password, tmp_passhash))

    @parameterized.expand(update_user_data)
    def test_update_user(self, username, password, first_name, last_name, is_active, scopes_list):
        self.logger.info("Running test_update_user")
        # FIXME: Add the values from the call?
        # Add all of the 'create_user_data' values via direct calls to redis
        
        # Retrieve the user data and change the values
        
        # Update the user via the datastore
        
        # Verify the correct data via direct calls to redis

    def tearDown(self):
        self.logger.info("Tearing down")
        # Flush the database again to be safe
        self.dstore.redis.flushdb()

# === MAIN ===
if __name__ == '__main__':
    # THIS SCRIPT SHOULD NEVER BE CALLED DIRECTLY
    # Call from the base directory of the package with the following command:
    # python3 -m unittest tests.<name_of_module>.<name_of_class>
    pass
