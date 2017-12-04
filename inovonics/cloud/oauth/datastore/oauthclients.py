#!/usr/bin/env python3

# === IMPORTS ===
import logging
import redpipe
import uuid

from inovonics.cloud.datastore import InoModelBase, InoObjectBase
from inovonics.cloud.datastore import DuplicateException, ExistsException, InvalidDataException, NotExistsException

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthClients(InoModelBase):
    def get_by_client_id(self, client_id):
        self.logger.debug("client_id: %s", client_id)
        oid = None
        with redpipe.autoexec() as pipe:
            oid = pipe.get("oauth:clients:client_id:{}".format(client_id))
        client_obj = self.get_by_oid(oid.result.decode('utf-8'))
        return client_obj

    def get_by_oid(self, oid, pipe=None):
        self.logger.debug("oid: %s", oid)
        client_obj = OAuthClient()
        with redpipe.autoexec(pipe) as pipe:
            db_obj = DBOAuthClient(oid, pipe)
            def cb():
                self.logger.debug("db_obj: %s", db_obj)
                if db_obj.persisted:
                    self.logger.debug("db_obj.persisted: True")
                    client_obj.set_fields((dict(db_obj)))
                else:
                    raise NotExistsException()
            pipe.on_execute(cb)
        return client_obj

    def create(self, clients):
        # If clients is a singular object, make it a list of one
        if not hasattr(clients, '__iter__'):
            clients = [clients]

        # Validate internal uniqueness
        self._validate_internal_uniqueness(clients)

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
            clients = [clients]

        # Validate internal uniqueness
        self._validate_internal_uniqueness(clients)

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
                self._upsert(client, pipe=pipe)

    def remove(self, client):
        with redpipe.autoexec() as pipe:
            pipe.srem("oauth:clients:client_ids", client.client_id)
            pipe.srem("oauth:clients:oids", client.oid)
            pipe.delete("oauth:clients:client_id:{}".format(client.client_id))
            pipe.delete("oauth:clients{{{}}}".format(client.oid))

    def _exists(self, client_id, pipe=None):
        with redpipe.autoexec(pipe=pipe) as pipe:
            exists = pipe.exists("oauth:clients:client_id:{}".format(client_id))
        return exists

    def _upsert(self, client, pipe=None):
        with redpipe.autoexec(pipe) as pipe:
            # Create/update the user and save it to redis
            db_obj = DBOAuthClient(client.get_dict(), pipe)
            # Remove empty custome fields from the object
            for field in client.fields_custom:
                if len(str(getattr(client, field)).strip()) == 0:
                    db_obj.remove(field, pipe=pipe)
            # Add the indexing data
            pipe.set("oauth:clients:client_id:{}".format(client.client_id), client.oid)
            pipe.sadd("oauth:clients:client_ids", client.client_id)
            pipe.sadd("oauth:clients:oids", client.oid)

    def _validate_internal_uniqueness(self, clients):
        client_ids = []
        oids = []
        for client in clients:
            client_ids.append(client.client_id)
            oids.append(client.oid)
        # If the length of the set is different from the list, duplicates exist
        if len(client_ids) != len(set(client_ids)) or len(oids) != len(set(oids)):
            raise DuplicateException()

class OAuthClient(InoObjectBase):
    """
    Class used to store and validate data for an OAuth Client entry.
    Passing data into the constructor will set all fields without returning any errors.
    Passing data into the .set_fields method will return a list of validation errors.
    """
    # 'oid' is the object's unique identifier.  This prevents collisions with the id() method.
    fields = [
        {'name': 'oid', 'type': 'uuid'},
        {'name': 'client_id', 'type': 'str'},
        {'name': 'name', 'type': 'str'},
        {'name': 'client_secret', 'type': 'str'},
        {'name': 'user', 'type': 'str'},
        {'name': 'is_confidential', 'type': 'bool'},
        {'name': 'allowed_grant_types', 'type': 'list'},
        {'name': 'redirect_uris', 'type': 'list'},
        {'name': 'default_scopes', 'type': 'list'},
        {'name': 'allowed_scopes', 'type': 'list'}
    ]

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
    keyspace = 'oauth:clients'
    key_name = 'oid'
    
    fields = {
        "client_id": redpipe.TextField,
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
        return "<DBOAuthClient: {}>".format(self['oid'])

# === MAIN ===
