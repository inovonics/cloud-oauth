#!/usr/bin/env python3

# === IMPORTS ===
import datetime
import dateutil.parser
import json
import logging
import redpipe
import uuid

from inovonics.cloud.datastore import InoModelBase
from inovonics.cloud.datastore import ExistsException, InvalidDataException, NotExistsException

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthTokens(InoModelBase):
    def get_by_id(self, token_id, pipe=None):
        token_obj = OAuthToken()
        with redpipe.autoexec(pipe)as pipe:
            db_obj = DBOAuthToken(token_id, pipe)

            def cb():
                if db_obj.persisted:
                    token_obj.set_fields((dict(db_obj)))
                else:
                    raise NotExistsException()

            pipe.on_execute(cb)
        return token_obj

    def get_by_access_token(self, access_token):
        # Look up the token by the access_token
        with redpipe.autoexec() as pipe:
            key = pipe.get("oauth:token:access:{}".format(access_token))
        return self.get_by_id(key.result.decode('utf-8'))

    def get_by_refresh_token(self, refresh_token):
        # Look up the token by the refresh_token
        with redpipe.autoexec() as pipe:
            key = pipe.get("oauth:token:refresh:{}".format(refresh_token))
        return self.get_by_id(key.result.decode('utf-8'))

    def create(self, tokens, expiry = 0):
        # If tokens is a singular object, make it a list of one
        if not hasattr(tokens, '__iter__'):
            tokens = [tokens]

        # Validate Redis uniqueness
        with redpipe.autoexec() as pipe:
            all_exists = []
            for token in tokens:
                all_exists.append(self._exists(token.token_id, pipe=pipe))

        # Return if any of the objects already exist
        for ex in all_exists:
            if ex.IS(True):
                raise ExistsException()

        # Create all the entries
        with redpipe.autoexec() as pipe:
            for token in tokens:
                self._upsert(token, expiry=expiry, pipe=pipe)

    def _exists(self, token_id, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            exists = pipe.exists('oauth:token{{{}}}'.format(token_id))
        return exists

    def _upsert(self, token, expiry = 0, pipe=None):
        with redpipe.autoexec(pipe) as pipe:
            # Create/update the token and save it to redis
            db_token = DBOAuthToken(token.get_all_dict(), pipe)
            # Add lookup keys for access and refresh tokens
            if expiry <= 0:
                # Set the secondary keys
                pipe.set("oauth:token:access:{}".format(token.access_token), token.token_id)
                pipe.set("oauth:token:refresh:{}".format(token.refresh_token), token.token_id)
            else:
                # Set the expiry on the struct
                pipe.expire("oauth:token{{{}}}".format(token.token_id), int(expiry))
                # Set the secondary keys
                pipe.set("oauth:token:access:{}".format(token.access_token), token.token_id, ex=int(expiry))
                pipe.set("oauth:token:refresh:{}".format(token.refresh_token), token.token_id, ex=int(expiry))

class OAuthToken:
    """
    Class used to store and validate data for a Token entry.
    Passing data into the constructor will set all fields without returning any errors.
    Passing data into the .set_fields method will return a list of validation errors.
    """
    
    fields = ['token_id', 'client_id', 'user', 'token_type', 'access_token', 'refresh_token', 'scopes']
    hidden_fields = []

    # Visible attributes
    token_id = ''
    client_id = ''
    user = ''
    token_type = ''
    access_token = ''
    refresh_token = ''
    expires = datetime.datetime.utcnow()
    scopes = []

    # Hidden attributes

    def __init__(self, dictionary=None):
        self.logger = logging.getLogger(type(self).__name__)
        self.token_id = str(uuid.uuid4())
        if dictionary:
            self.set_fields(dictionary)

    def __repr__(self):
        return "<OAuthToken {}>".format(self.token_id)

    def get_dict(self):
        # Get all fields in the object as a dict (excluding hidden fields)
        dictionary = {}
        for field in self.fields:
            dictionary[field] = getattr(self, field)
        # Special handling of the datetime
        dictionary['expires'] = self.expires.isoformat()
        self.logger.debug("Expire Time: {}".format(dictionary['expires']))
        return dictionary

    def get_all_dict(self):
        # Get all fields in the object as a dict
        dictionary = self.get_dict()
        for field in self.hidden_fields:
            dictionary[field] = getattr(self, field)
        return dictionary

    def set_fields(self, dictionary):
        if not dictionary:
            return self._validate_fields()
        for field in self.fields + self.hidden_fields:
            if field in dictionary and dictionary[field]:
                setattr(self, field, dictionary[field])
        # Special handling of the datetime
        self.expires = dateutil.parser.parse(dictionary['expires'])
        self.logger.debug("Expire Time: {}".format(self.expires))
        self.logger.debug("UTCNow: {}".format(datetime.datetime.utcnow()))
        return self._validate_fields()

    def _validate_fields(self):
        errors = []
        # FIXME: Add validation here.
        return errors

class DBOAuthToken(redpipe.Struct):
    keyspace = 'oauth:token'
    key_name = 'token_id'

    fields = {
        "client_id": redpipe.TextField,
        "user": redpipe.TextField,
        "token_type": redpipe.TextField,
        "access_token": redpipe.TextField,
        "refresh_token": redpipe.TextField,
        "expires": redpipe.TextField,
        "scopes": redpipe.ListField
    }

    def __repr__(self):
        return "<DBOAuthToken {}>".format(self['token_id'])

# === MAIN ===
