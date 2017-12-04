#!/usr/bin/env python3

# === IMPORTS ===
from flask.views import View

from .__version__ import __version__

# === GLOBALS ===

# === FUNCTIONS ===
def oauth_register_handlers(app, oauth, token_path, revoke_path=None):
    # Register the token handler to the app.
    OAuthTokenHandler.decorators = [oauth.token_handler]
    app.add_url_rule(token_path, view_func=OAuthTokenHandler.as_view('oauth_token_handler'))
    # Register the revoke handler to the app if the path is specified
    if revoke_path:
        OAuthRevokeHandler.decorators = [oauth.revoke_handler]
        app.add_url_rule(revoke_path, view_func=OAuthRevokeHandler.as_view('oauth_revoke_handler'))

# === CLASSES ===
class OAuthTokenHandler(View):
    methods = ['POST']

    def dispatch_request(self):
        dispatch_info = {}
        dispatch_info['version'] = __version__
        return dispatch_info

class OAuthRevokeHandler(View):
    methods = ['POST']

    def dispatch_request(self):
        pass

# === MAIN ===
