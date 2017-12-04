#!/usr/bin/env python3

# === IMPORTS ===
import logging
import redpipe
import uuid

from passlib.hash import pbkdf2_sha512

from inovonics.cloud.datastore import InoModelBase, InoObjectBase
from inovonics.cloud.datastore import DuplicateException, ExistsException, InvalidDataException, NotExistsException

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthUsers(InoModelBase):
    def get_usernames(self, pipe=None):
        key_future = redpipe.Future()
        with redpipe.autoexec(pipe) as pipe:
            byte_set = pipe.smembers('oauth:users:usernames')

            # After executing the pipe, callback to decode the results
            def cb():
                key_list = []
                for byte_value in byte_set:
                    key_list.append(byte_value.decode("utf-8"))
                key_future.set(key_list)
                # Execute the callback

            pipe.on_execute(cb)
        return key_future

    def get_ids(self, pipe=None):
        key_future = redpipe.Future()
        with redpipe.autoexec(pipe) as pipe:
            byte_set = pipe.smembers('oauth:users:oids')

            # After executing the pipe, callback to decode the results
            def cb():
                key_list = []
                for byte_value in byte_set:
                    key_list.append(byte_value.decode("utf-8"))
                key_future.set(key_list)
                # Execute the callback

            pipe.on_execute(cb)
        return key_future

    def get_by_id(self, user_id, pipe=None):
        user_obj = OAuthUser()
        with redpipe.autoexec(pipe)as pipe:
            db_obj = DBOAuthUser(user_id, pipe=pipe)

            def cb():
                if db_obj.persisted:
                    user_obj.set_fields((dict(db_obj)))
                else:
                    raise NotExistsException()

            pipe.on_execute(cb)
        return user_obj

    def get_user_id(self, username, pipe=None):
        decoded_user_id = redpipe.Future()
        with redpipe.autoexec(pipe=pipe) as pipe:
            user_id = pipe.get('oauth:users:{}'.format(username))

            def cb():
                if not user_id:
                    raise NotExistsException()
                decoded_user_id.set(user_id.decode("utf-8"))
            
            pipe.on_execute(cb)
        return decoded_user_id

    def create(self, users):
        # If users is a singular object, make it a list of one
        if not hasattr(users, '__iter__'):
            users = [users]

        # Validate internal uniqueness
        self._validate_internal_uniqueness(users)

        # Validate Redis uniqueness
        # FIXME: This should check user_id and username (which is more important) for uniqueness
        with redpipe.autoexec() as pipe:
            all_names = self.get_usernames(pipe)
            all_exists = []
            for user in users:
                all_exists.append(self._exists(user.oid, pipe=pipe))

        # Return if any of the objects already exist
        for ex in all_exists:
            if ex.IS(True):
                raise ExistsException()

        for user in users:
            if user.username in all_names:
                raise ExistsException()

        # Create all the entries
        with redpipe.autoexec() as pipe:
            for user in users:
                self._upsert(user, pipe=pipe)

    def update(self, users):
        # If users is a singular object, make it a list of one
        if not hasattr(users, '__iter__'):
            users = [users]

        # Validate internal uniqueness
        self._validate_internal_uniqueness(users)

        # Validate objects exist in Redis
        with redpipe.autoexec() as pipe:
            all_exists = []
            for user in users:
                all_exists.append(self._exists(user.oid, pipe=pipe))
        # Return if any of the objects don't already exist
        for ex in all_exists:
            if ex.IS(False):
                raise NotExistsException()

        # Update all the entries
        with redpipe.autoexec() as pipe:
            for user in users:
                self._upsert(user, pipe=pipe)

    def update_password(self, user_id, old_password, new_password):
        # Validate given data
        # FIXME: Add password complexity checks here.

        # Try to get the user (will raise exception if not found)
        user = self.get_user(get_by_id)

        # Check the password and update it
        if user.check_password(old_password):
            user.update_password(new_password)
            self._upsert(user)
        else:
            raise InvalidDataException

    def remove(self, oauth_user):
        with redpipe.autoexec() as pipe:
            pipe.srem('oauth:users:usernames', oauth_user.username)
            pipe.srem('oauth:users:oids', oauth_user.oid)
            pipe.delete('oauth:users:{}'.format(oauth_user.username))
            pipe.delete('oauth:users{{{}}}'.format(oauth_user.oid))

    def _exists(self, user_id, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            exists = pipe.exists('oauth:users{{{}}}'.format(user_id))
        return exists

    def _upsert(self, oauth_user, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            # Create/update the user and save it to redis
            db_user = DBOAuthUser(oauth_user.get_dict(), pipe=pipe)
            # Remove empty custom fields from the object
            for field in oauth_user.fields_custom:
                if len(str(getattr(oauth_user, field)).strip()) == 0:
                    db_obj.remove(field, pipe=pipe)
            # Add the user to the usernames set
            pipe.set('oauth:users:{}'.format(oauth_user.username), oauth_user.oid)
            pipe.sadd('oauth:users:usernames', oauth_user.username)
            pipe.sadd('oauth:users:oids', oauth_user.oid)

    def _validate_internal_uniqueness(self, users):
        usernames = []
        oids = []
        for user in users:
            usernames.append(user.username)
            oids.append(user.oid)
        # If the length of the set is different from the list, duplicates exist
        if len(usernames) != len(set(usernames)) or len(oids) != len(set(oids)):
            raise DuplicateException()

class OAuthUser(InoObjectBase):
    """
        Class used to store and validate data for a User entry.
        Passing data into the constructor will set all fields without returning any errors.
        Passing data into the .set_fields method will return a list of validation errors.
    """
    fields = [
        {'name': 'oid', 'type': 'uuid'},
        {'name': 'username', 'type': 'str'},
        {'name': 'password_hash', 'type': 'str'},
        {'name': 'is_active', 'type': 'bool'},
        {'name': 'scopes', 'type': 'list'}
    ]

    def __init__(self, dictionary=None):
        super().__init__()
        # Override default data
        setattr(self, 'is_active', True)
        # Add validation methods to list
        self.validation_methods.append(self._validate_username)
        self.validation_methods.append(self._validate_is_active)
        self.validation_methods.append(self._validate_scopes)
        if dictionary:
            self.set_fields(dictionary)

    def _validate_username(self):
        # Ensure username is present, a string, and less than 128 chars
        if not isinstance(getattr(self, 'username'), str):
            return "{} not of type str but type {}, value {}".format(
                'username', type(getattr(self, 'username')), getattr(self, 'username'))
        if len(getattr(self, 'username')) > 127:
            return "{} must be less than 128 chars".format('username')
        return None

    def _validate_is_active(self):
        # Ensure is_active is present and a boolean
        if not isinstance(getattr(self, 'is_active'), bool):
            return "{} not of type bool but type {}, value {}".format(
                'is_active', type(getattr(self, 'is_active')), getattr(self, 'is_active'))
        return None

    def _validate_scopes(self):
        # Ensure scopes is present and a list
        if not isinstance(getattr(self, 'scopes'), list):
            return "{} not of type list but type {}, value {}".format(
                'scopes', type(getattr(self, 'scopes')), getattr(self, 'scopes'))
        return None

    def check_password(self, password):
        return pbkdf2_sha512.verify(password, self.password_hash)

    def update_password(self, new_password):
        self.password_hash = pbkdf2_sha512.hash(new_password)

class DBOAuthUser(redpipe.Struct):
    keyspace = 'oauth:users'
    key_name = 'oid'

    fields = {
        "username": redpipe.TextField,
        "password_hash": redpipe.TextField,
        "is_active": redpipe.BooleanField,
        "scopes": redpipe.ListField
    }

    def __repr__(self):
        return "<DBOAuthUser: {}>".format(self['oid'])

# === MAIN ===
