#!/usr/bin/env python3

# === IMPORTS ===
import logging
import os

from flask import Flask

from inovonics.cloud.datastore import InoRedis
from inovonics.cloud.oauth import InoOAuth2Provider, oauth_register_handlers

from inovonics.cloud.oauth import OAuthClients, OAuthClient, OAuthUsers, OAuthUser

# === GLOBALS ===
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = os.getenv('REDIS_PORT', 6379)
REDIS_DB = os.getenv('REDIS_DB', 0)

dstore = InoRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

app = Flask(__name__)

oauth = InoOAuth2Provider(app, dstore)
#app.add_url_rule('/oauth/token', view_func=oauth.token_handler(OAuthTokenHandler.as_view('oauth_token_handler')))
#app.add_url_rule('/oauth/revoke', view_func=OAuthRevokeHandler.as_view('oauth_revoke_handler'))
oauth_register_handlers(app, oauth, token_path='/oauth/token', revoke_path='/oauth/revoke')

# === FUNCTIONS ===
@app.before_first_request
def db_init():
    # This flushes the Redis database and pushed a default user and a couple of default clients into the database.
    dstore.redis.flushdb()
    users = OAuthUsers(dstore)
    clients = OAuthClients(dstore)
    
    user1_data = {
        'username': 'admin@example.com',
        'first_name': 'Admin',
        'last_name': 'Testuser',
        'is_active': True,
        'scopes': ['protected']
    }
    user1 = OAuthUser(user1_data)
    user1.update_password('<insert_password_here>')
    users.create(user1)
    
    client1_data = {
        'name': 'Test Client One',
        'client_id': '<insert_client_id_here>', # API_KEY
        'client_secret': '', # API_SECRET
        'user': 'admin@example.com',
        'is_confidential': False,
        'allowed_grant_types': ['password'],
        'redirect_uris': [],
        'default_scopes': ['protected'],
        'allowed_scopes': ['protected']
    }
    client1 = OAuthClient(client1_data)
    clients.create(client1)

@app.route('/')
def static_root():
    return app.send_static_file('index.html')

@app.route('/protected/')
@oauth.require_oauth('protected')
def protected_page():
    return app.send_static_file('protected.html')

# === CLASSES ===

# === MAIN ===
def main():
    # Allow non-TLS protected requests for testing
    os.environ['DEBUG'] = 'true'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    
    # Enable DEBUG logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Make the magic happen
    app.run(debug=True, host='0.0.0.0', port=8080)

if __name__ == '__main__':
    main()
