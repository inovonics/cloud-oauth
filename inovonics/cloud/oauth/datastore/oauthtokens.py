#!/usr/bin/env python3

# Disabling some unhappy pylint things
# pylint: disable=no-name-in-module,import-error,redefined-argument-from-local,no-self-use

# === IMPORTS ===
import redpipe

from inovonics.cloud.datastore import InoModelBase, InoObjectBase
from inovonics.cloud.datastore import ExistsException, NotExistsException

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthTokens(InoModelBase):
    def get_by_id(self, token_id, pipe=None):
        token_obj = OAuthToken()
        with redpipe.autoexec(pipe=pipe)as pipe:
            db_obj = DBOAuthToken(token_id, pipe)
            def callback():
                if db_obj.persisted:
                    token_obj.set_fields((dict(db_obj)))
                else:
                    raise NotExistsException()
            pipe.on_execute(callback)
        return token_obj

    def get_by_access_token(self, access_token):
        # Look up the token by the access_token
        with redpipe.autoexec() as pipe:
            oid = pipe.get("oauth:tokens:access:{}".format(access_token))
        if oid.IS(None):
            raise NotExistsException()
        return self.get_by_id(oid.result.decode('utf-8'))

    def get_by_refresh_token(self, refresh_token):
        # Look up the token by the refresh_token
        with redpipe.autoexec() as pipe:
            oid = pipe.get("oauth:tokens:refresh:{}".format(refresh_token))
        if oid.IS(None):
            raise NotExistsException()
        return self.get_by_id(oid.result.decode('utf-8'))

    def create(self, tokens, expiry=0):
        # If tokens is a singular object, make it a list of one
        if not hasattr(tokens, '__iter__'):
            tokens = [tokens]

        # Validate Redis uniqueness
        with redpipe.autoexec() as pipe:
            all_exists = []
            for token in tokens:
                all_exists.append(self._exists(token.oid, pipe=pipe))

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
            exists = pipe.exists('oauth:tokens{{{}}}'.format(token_id))
        return exists

    def _upsert(self, token, expiry=0, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            # Create/update the token and save it to redis
            db_token = DBOAuthToken(token.get_dict(), pipe)
            # Remove empty custome fields from the object
            for field in token.fields_custom:
                if not str(getattr(token, field)).strip():
                    db_token.remove(field, pipe=pipe)
            # Add lookup keys for access and refresh tokens
            if expiry <= 0:
                # Set the secondary keys
                pipe.set("oauth:tokens:access:{}".format(token.access_token), token.oid)
                pipe.set("oauth:tokens:refresh:{}".format(token.refresh_token), token.oid)
            else:
                # Set the expiry on the struct
                pipe.expire("oauth:tokens{{{}}}".format(token.oid), int(expiry) * 24)
                # Set the secondary keys
                pipe.set("oauth:tokens:access:{}".format(token.access_token), token.oid, ex=int(expiry))
                pipe.set("oauth:tokens:refresh:{}".format(token.refresh_token), token.oid, ex=(int(expiry) * 24))

class OAuthToken(InoObjectBase):
    """
    Class used to store and validate data for a Token entry.
    Passing data into the constructor will set all fields without returning any errors.
    Passing data into the .set_fields method will return a list of validation errors.
    """
    # Disabling somethings until more validation can be added
    # pylint: disable=too-few-public-methods
    fields = [
        {'name': 'oid', 'type': 'uuid'},
        {'name': 'client_id', 'type': 'str'},
        {'name': 'user', 'type': 'str'},
        {'name': 'token_type', 'type': 'str'},
        {'name': 'access_token', 'type': 'str'},
        {'name': 'refresh_token', 'type': 'str'},
        {'name': 'expires', 'type': 'datetime'},
        {'name': 'scopes', 'type': 'list'}
    ]

class DBOAuthToken(redpipe.Struct):
    keyspace = 'oauth:tokens'
    key_name = 'oid'

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
        return "<DBOAuthToken: {}>".format(self['oid'])

# === MAIN ===
