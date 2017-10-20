#!/usr/bin/env python3

# === IMPORTS ===

# === GLOBALS ===

# === FUNCTIONS ===

# === CLASSES ===
class OAuthTokenHandler(View):
    methods = ['POST']

    @oauth.token_handler
    def dispatch_request(self):
        users = Users(dstore)
        
        dispatch_info = {}
        dispatch_info['version'] = __version__

        try:
            user_id = users.get_user_id(request.form.get('username'))
            user = users.get_user(user_id.result)
            dispatch_info['user_id'] = user.user_id
            dispatch_info['username'] = user.username
            dispatch_info['first_name'] = user.first_name
            dispatch_info['last_name'] = user.last_name
        except ExistsException:
            logging.debug("No user info available, must be client key/secret.")

        return dispatch_info

class OAuthRevokeHandler(View):
    methods = ['POST']

    @oauth.revoke_handler
    def dispatch_request(self):
        pass

# === MAIN ===
