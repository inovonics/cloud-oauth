#!/usr/bin/env python3

# === IMPORTS ===
import logging

from flask.views import View

from .__version__ import __version__

# === GLOBALS ===

# === FUNCTIONS ===
# Need a handler registration function...  Or need to super the init function.
def oauth_register_handlers(app, oauth, token_path, revoke_path = None):
    # Register the token handler to the app.
    OAuthTokenHandler.decorators = [oauth.token_handler]
    app.add_url_rule(token_path, view_func=OAuthTokenHandler.as_view('oauth_token_handler'))
    # Register the revoke handler to the app if the path is specified
    if revoke_path:
        OAuthRevokeHandler.decorators = [oauth.revoke_handler]
        app.add_url_rule(revoke_path, view_func=OAuthRevokeHandler.as_view('oauth_revoke_handler'))
    # FIXME: Just trying to get this to work.  This should modify the app in place, not have to return the app.
    #return app

# === CLASSES ===
class OAuthTokenHandler(View):
    methods = ['POST']

    #@oauth.token_handler
    def dispatch_request(self):
        dispatch_info = {}
        dispatch_info['version'] = __version__
        return dispatch_info

class OAuthRevokeHandler(View):
    methods = ['POST']

    #@oauth.revoke_handler
    def dispatch_request(self):
        pass

# === MAIN ===
