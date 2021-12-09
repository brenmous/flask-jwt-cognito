# flask-jwt-cognito
Integration with AWS Cognito for [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended).

Intended to make a Cognito oauth2 code grant flow easier to work with.

This is a fledgling project that is just factoring out some shared functionality from two Flask
projects. Hopefully I get around into turning it into something more robust.

Install with `pip install git+https://github.com/brenmous/flask-jwt-cognito`.

Tested with Python 3.8, likely to work with 3.7.

## Using

Requires config items set for `flask-jwt-extended`:
- `JWT_TOKEN_LOCATION`: `["cookies"]`
- `JWT_COOKIE_SECURE`: `True`
- `JWT_ALGORITHM`: `"RS256"`

These store the JWT access and refresh tokens as secure cookies.
The algorithm depends on what Cognito is using. I believe in most cases
it's RS256, but to confirm you can check the JWK for your cognito provider at
`https://cognito-idp.<region>.amazonaws.com/<region>-<id>/.well-known/jwks.json`.

Beyond these, configure `flask-jwt-extended` as you normally would.

Config items for `flask-jwt-cognito`:
- `JWT_COGNITO_ID`: Client ID of the Cognito client
- `JWT_COGNITO_SECRET`: Client secret of the Cognito client
- `JWT_COGNITO_PROVIDER`: The provider AKA issuer URL, e.g. `https://cognito-idp.<region>.amazonaws.com/<region>-<id>`- `JWT_COGNITO_URL`: Your Cognito authorization URL, e.g. `https://auth.my.org`

Initalise using your Flask application and an instance of `flask-jwt-extended JWTManager`:

Single app:
```
app = Flask()
jwt = JWTManager(app=app)
jwtc = FlaskJWTCognito(app=app, jwt_manager=jwt)
```

Factory (I initialise `JWTManager` and `FlaskJWTExtended` in an extensions module`):
```
# in extenions.py
jwt = JWTManager()
jwtc = FlaskJWTCognito(jwt_manager=jwt)

# in __init__.py
app = Flask()
jwt.init_app(app)
jwtc.init_app(app)
```

Usage example:
```
from flask import url_for, render_template, current_app as app
from my_package.extensions import jwt, jwtc

# 'optional=True' in jwt_required decorator: auth not required for login, 
#  but triggers auth callbacks
@app.route('/login', methods=["GET"])
@jwt_required(optional=True)  
def login():
    try:
        return jwtc.login(url_for('app.index'))
    except Exception:
        # Handle the error as desired and return a response
        return render_template("auth_error.html")

@app.route('/logout', methods=["GET"])
@jwt_required(optional=True)
def logout():
    return jwtc.logout()
```

If the current implementation is too restrictive, you can still browse the code for the 
`FlaskJWTCognito` class to see examples of fetching and decoding JWTs from Cognito, and storing
access and refresh tokens as cookies for authorization.
