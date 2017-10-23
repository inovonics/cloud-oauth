#!/usr/bin/env python3

# === IMPORTS ===
import logging
import redpipe
import uuid

from inovonics.cloud.datastore import InoModelBase
from inovonics.cloud.datastore import ExistsException, InvalidDataException, NotExistsException

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthClients(InoModelBase):
    def get_by_id(self, client_id, pipe=None):
        client_obj = OAuthClient()
        with redpipe.autoexec(pipe)as pipe:
            db_obj = DBOAuthClient(client_id, pipe)

            def cb():
                if db_obj.persisted:
                    client_obj.set_fields((dict(db_obj)))
                else:
                    raise NotExistsException()

            pipe.on_execute(cb)
        return client_obj

    def create(self, clients):
        # If clients is a singular object, make it a list of one
        if not hasattr(clients, '__iter__'):
            clients = [clients]

        # Validate Redis uniqueness
        with redpipe.autoexec() as pipe:
            all_exists = []
            for client in clients:
                all_exists.append(self._exists(client.client_id, pipe=pipe))

        # Return if any of the objects already exist
        for ex in all_exists:
            if ex.IS(True):
                raise ExistsException()

        # Create all the entries
        with redpipe.autoexec() as pipe:
            for client in clients:
                self._upsert(client, pipe=pipe)

    def update(self, clients):
        # If clients is a singular object, make it a list of one
        if not hasattr(clients, '__iter__'):
            users = [users]

        # Validate objects exist in Redis
        with redpipe.autoexec() as pipe:
            all_exists = []
            for client in clients:
                all_exists.append(self._exists(client.client_id, pipe=pipe))

        # Return if any of the objects don't already exist
        for ex in all_exists:
            if ex.IS(False):
                raise NotExistsException()

        # Update all the entries
        with redpipe.autoexec() as pipe:
            for client in clients:
                self._upsert_user(client, pipe=pipe)

    def remove(self, client_id):
        with redpipe.autoexec() as pipe:
            key = 'oauth:client{{{}}}'.format(client_id)
            pipe.delete(key)

    def _exists(self, client_id, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            exists = pipe.exists('oauth:client{{{}}}'.format(client_id))
        return exists

    def _upsert(self, client, pipe=None):
        with redpipe.autoexec(pipe) as pipe:
            # Create/update the user and save it to redis
            db_obj = DBOAuthClient(client.get_all_dict(), pipe)

class OAuthClient:
    """
    Class used to store and validate data for an OAuth Client entry.
    Passing data into the constructor will set all fields without returning any errors.
    Passing data into the .set_fields method will return a list of validation errors.
    """

    fields = [
        'client_id', 'name', 'client_secret', 'user', 'is_confidential', 'allowed_grant_types', 'redirect_uris',
        'default_scopes', 'allowed_scopes'
    ]
    hidden_fields = []

    # Visible attributes
    client_id = ''
    name = ''
    client_secret = ''
    user = ''
    is_confidential = False
    allowed_grant_types = []
    redirect_uris = []
    default_scopes = []
    allowed_scopes = []

    # Hidden attributes

    def __init__(self, dictionary=None):
        self.logger = logging.getLogger(type(self).__name__)
        self.client_id = str(uuid.uuid4())
        if dictionary:
            self.set_fields(dictionary)

    def __repr__(self):
        return "<OAuthClient {}>".format(self.client_id)

    def get_dict(self):
        # Get all fields in the object as a dict (excluding hidden fields)
        dictionary = {}
        for field in self.fields:
            dictionary[field] = getattr(self, field)
        return dictionary

    def get_all_dict(self):
        # Get all fields in the object as a dict
        dictionary = {}
        for field in self.fields:
            dictionary[field] = getattr(self, field)
        for field in self.hidden_fields:
            dictionary[field] = getattr(self, field)
        return dictionary

    def set_fields(self, dictionary):
        if not dictionary:
            return self._validate_fields()
        for field in self.fields + self.hidden_fields:
            if field in dictionary and dictionary[field]:
                setattr(self, field, dictionary[field])
        return self._validate_fields()

    def _validate_fields(self):
        errors = []
        # FIXME: Add validation here.
        return errors
    
    # Special properties for the OAuth handlers
    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def default_redirect_uri(self):
        if len(self.redirect_uris) > 0:
            return self.redirect_uris[0]
        return '' # Bypassing redirects if none set
    
    def validate_scopes(self, in_scopes):
        # OAuth method to test if the requested scopes are in the allowed list.
        # This is to override the _default_scopes list being used as the allowed list.
        return set(self.allowed_scopes).issuperset(set(in_scopes))

class DBOAuthClient(redpipe.Struct):
    keyspace = 'oauth:client'
    key_name = 'client_id'
    
    fields = {
        "name": redpipe.TextField,
        "client_secret": redpipe.TextField,
        "user": redpipe.TextField,
        "is_confidential": redpipe.BooleanField,
        "allowed_grant_types": redpipe.ListField,
        "redirect_uris": redpipe.ListField,
        "default_scopes": redpipe.ListField,
        "allowed_scopes": redpipe.ListField
    }

    def __repr__(self):
        return "<DBOAuthClient {}>".format(self['client_id'])

# === MAIN ===
