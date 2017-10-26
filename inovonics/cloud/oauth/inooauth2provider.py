#!/usr/bin/env python3

# === IMPORTS ===
import datetime
import logging

from flask import g

from flask_oauthlib.provider import OAuth2Provider

from inovonics.cloud.datastore import NotExistsException

from .datastore import OAuthClients, OAuthClient
from .datastore import OAuthTokens, OAuthToken
from .datastore import OAuthUsers, OAuthUser

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class InoOAuth2Provider(OAuth2Provider):
    def __init__(self, app=None, dstore=None):
        super().__init__(app)
        self.logger = logging.getLogger(type(self).__name__)
        if dstore:
            self.init_dstore(dstore)

    def init_dstore(self, dstore):
        self.dstore = dstore

    def _clientgetter(self, client_id):
        self.logger.debug("client_id: %s", client_id)
        clients = OAuthClients(self.dstore)
        client = clients.get_by_id(client_id)
        # Save the client to the request scratch area and return the client
        g.oauth_current_client = client
        return client

    def _grantgetter(self, client_id, code):
        return None  # Grant tokens currently not allowed

    def _grantsetter(self, client_id, code, request, *args, **kwargs):
        return None  # Grant tokens currently not allowed

    def _tokengetter(self, access_token=None, refresh_token=None):
        self.logger.debug("access_token: %s, refresh_token: %s", access_token, refresh_token)
        tokens = OAuthTokens(self.dstore)
        try:
            token = None
            if access_token:
                token = tokens.get_by_access_token(access_token)
            elif refresh_token:
                token = tokens.get_by_refresh_token(refresh_token)
            self.logger.debug("Token Expiry: %s", token.expires)
            # Save the token to the request scratch area and return the token
            g.oauth_current_token = token
            return token
        except NotExistsException:
            self.logger.debug("Token does not exist.")
        return None

    def _tokensetter(self, otoken, request, *args, **kwargs):
        self.logger.debug("OToken: %s", otoken)
        tokens = OAuthTokens(self.dstore)

        expires_in = otoken['expires_in']
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        self.logger.debug("New Token Expires: %s", expires)

        token = OAuthToken()
        token.access_token = otoken['access_token']
        token.refresh_token = otoken.get('refresh_token')
        token.token_type = otoken['token_type']
        token.scopes = otoken['scope']
        token.expires = expires
        token.client_id = request.client.client_id
        if type(request.user) == OAuthUser:
            self.logger.debug("Setting user data in OAuth token")
            token.user = request.user.username
            # Overriding the scopes from the user for now.
            # FIXME: The OAuth2RequestValidator should be subclassed and
            #        this should be fixed in the get_default_scopes method.
            token.scopes = request.user.scopes
            otoken['scope'] = request.user.scopes
        else:
            token.user = ''

        # Make sure the scopes value is a list (sometimes comes in as a string)
        if isinstance(token.scopes, str):
            token.scopes = [token.scopes]

        tokens.create(token, expires_in)
        return token

    def _usergetter(self, username, password, *args, **kwargs):
        self.logger.debug("username: %s, password: %s", username, password)
        users = OAuthUsers(self.dstore)
    
        try:
            user_id = users.get_user_id(username)
            user = users.get_by_id(user_id.result)
        except NotExistsException:
            return None
    
        # Password Check
        if user.check_password(password):
            # Save the user to the request scratch area and return the user
            g.oauth_current_user = user
            return user
        return None

# === MAIN ===
