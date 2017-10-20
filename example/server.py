#!/usr/bin/env python3

# === IMPORTS ===
import logging
import os

from flask import Flask

from inovonics.cloud.datastore import InoRedis
from inovonics.cloud.oauth import InoOAuth2Provider

# === GLOBALS ===
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = os.getenv('REDIS_PORT', 6379)
REDIS_DB = os.getenv('REDIS_DB', 0)

dstore = InoRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

app = Flask(__name__)

oauth = InoOAuth2Provider(app, dstore)
# FIXME: Register the OAuth handlers here.

# === FUNCTIONS ===
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
