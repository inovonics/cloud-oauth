#!/usr/bin/env python3

# === IMPORTS ===
import logging

from flask_oauthlib.provider import OAuth2Provider

from inovonics.cloud.datastore import NotExistsException

from .datastore import OAuthClients, OAuthClient
from .datastore import OAuthTokens, OAuthToken
from .datastore import OAuthUsers, OAuthUser

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class InoOAuth2Provider(OAuth2Provider):
    def __init__(self, app=None, dstore):
        super().__init__(app)
        self.logger = logging.getLogger(type(self).__name__)
        self.dstore = dstore
        
    def _clientgetter(self, client_id):
        pass
    
    def _grantgetter(self, client_id, code):
        return None  # Grant tokens currently not allowed
    
    def _grantsetter(self, client_id, code, request, *args, **kwargs):
        return None  # Grant tokens currently not allowed
    
    def _tokengetter(self, access_token=None, refresh_token=None):
        logging.debug("Access Token: %s, Refresh Token: %s", access_token, refresh_token)
        tokens = OAuthTokens(dstore)
        try:
            token = None
            if access_token:
                token = tokens.get_by_access_token(access_token)
            elif refresh_token:
                token = tokens.get_by_refresh_token(refresh_token)
            logging.debug("Token Expiry: {}".format(token.expires))
            return token
        except NotExistsException:
            logging.info("Token does not exist.")
        return None
    
    def _tokensetter(self, otoken, request, *args, **kwargs):
        pass
    
    def _usergetter(self, username, password, *args, **kwargs):
        pass

# === MAIN ===
