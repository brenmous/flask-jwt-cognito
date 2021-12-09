"""
Handles logging in and out and interacting with Cognito oauth2.

Auth is handled by flask_jwt_extended. To protect a route, decorate it
with the @jwt_required decorator.

Note the use of the `optional` parameter in this decorator. I've used
this in cases where authorization isn't nessecary, but we still want
flask_jwt_extended to attempt an authorization workflow so it will
trigger callbacks.
"""
from typing import Tuple, TypeVar, Optional

from flask import current_app
from flask import Response as FlaskResponse
from werkzeug import Response as WerkzeugResponse
from flask import url_for, redirect, request, make_response, render_template
from flask_jwt_extended import (
    set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies
)
from flask_jwt_extended import JWTManager
from flask_jwt_extended.config import config as jwt_config
from jwcrypto import jwk as jwkc
import requests

ResponseType = TypeVar('ResponseType', FlaskResponse, WerkzeugResponse)

class FlaskJWTCognito:
    def __new__(cls, *args, **kwargs):
        try:
            return current_app.extensions["flask-jwt-cognito"]
        except (KeyError, RuntimeError):
            return super().__new__(cls, *args, **kwargs)

    def __init__(
            self,
            jwt_manager: JWTManager,
            decode_key_loader_callback: Optional[callable] = None,
            expired_token_loader_callback: Optional[callable] = None,
            app=None

    ):
        if app is not None:
            self.init_app(app)

        self.jwt_manager = jwt_manager

        if decode_key_loader_callback is not None:
            self.decode_key_loader_callback = decode_key_loader_callback
        self.jwt_manager._decode_key_callback = self.decode_key_loader_callback

        if expired_token_loader_callback is not None:
            self.expired_token_loader_callback = expired_token_loader_callback
        self.jwt_manager._expired_token_callback = self.expired_token_loader_callback

    def init_app(self, app):
        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["flask-jwt-cognito"] = self
        app.config.setdefault('JWT_COGNITO_URL', None)
        app.config.setdefault('JWT_COGNITO_PROVIDER', None)
        app.config.setdefault('JWT_COGNITO_ID', None)
        app.config.setdefault('JWT_COGNITO_SECRET', None)
        app.config.setdefault('JWT_COOKIE_SECURE', True)
        app.config.setdefault('JWT_TOKEN_LOCATION', ["cookies"])
        app.config.setdefault('JWT_ALGORITHM', "RS256")
        app.config.setdefault('JWT_COOKIE_CSRF_PROTECT', True)

    def _decode_key_loader_callback(self, headers: dict, payload: dict) -> str:
        """
        A custom decode key loader, called by JWT library when it needs
        to decode a JWT. We source the decode keys from the congito
        JSON web key sets.

        Parameters
        ----------
        headers
            Header data of the unverified JWT.
        payload
            Payload data of the unverified JWT.

        Returns
        -------
        str
            The decoded JWT.
        """
        r = requests.get(current_app.config["JWT_COGNITO_PROVIDER"] + '/.well-known/jwks.json')
        keys = r.json()['keys']
        for k in keys:
            if k['kid'] == headers['kid']:
                jwk = jwkc.JWK(**k)
                return jwk.export_to_pem().decode('utf-8')
        raise ValueError("jwt decode key not found")

    def _expired_token_loader_callback(self, headers: dict, payload: dict) -> ResponseType:
        """
        Refreshes an expired token, triggered when a user makes a request
        with an expired token. If they have a valid token, this is spent
        for a new access token. If they don't or, or token refresh fails,
        they are directed to log in again.

        Parameters
        ----------
        headers
            Header data of the unverified JWT.
        payload
            Payload data of the unverified JWT.

        Returns
        -------
        ResponseType
        """
        try:
            refresh_token = request.cookies.get(jwt_config.refresh_cookie_name)
            if refresh_token is None:
                raise ValueError("Refresh cookie not found")
            access_token = self._spend_refresh_token(refresh_token)
            response = make_response(redirect(request.path))
            set_access_cookies(response, access_token)
        except Exception:
            response = make_response(
                render_template('error.html', msg="Authorization has expired. Please log in again."),
                401
            )
            unset_jwt_cookies(response)
        return response

    def _auth_code_url(logout: bool = False) -> str:
        """
        Constructs the authorization URL for the Cognito application.

        Parameters
        ----------
        logout
            If true, redirects users to the URL that triggers the
            logout workflow.

        Returns
        -------
        str
            The URL.
        """
        cognito_url = current_app.config['JWT_COGNITO_URL']
        cognito_id = current_app.config['JWT_COGNITO_ID']
        redirect_uri = request.url_root + url_for('auth.login').lstrip('/')
        return (f"{cognito_url}/{'logout' if logout else 'login'}"
                f"?response_type=code&client_id={cognito_id}&redirect_uri={redirect_uri}")

    def _get_tokens(auth_code: str) -> Tuple[str, str]:
        """
        Fetches an access token and refresh token for a user from
        Cognito.

        Parameters
        ----------
        auth_code
            The authorization code returned by the code grant workflow.
            This is present as a URL query string after the user signs
            in with SSO and is redirected back to the application.

        Returns
        -------
        Tuple[str, str]
            A tuple containing an access token and refresh token.
        """
        cognito_id = current_app.config["JWT_COGNITO_ID"]
        cognito_secret = current_app.config["JWT_COGNITO_SECRET"]
        auth_url = current_app.config["JWT_COGNITO_URL"]
        redirect_uri = request.url_root + url_for('auth.login').lstrip('/')
        data = {
            'grant_type': 'authorization_code',
            'client_id': cognito_id,
            'redirect_uri': redirect_uri,
            'code': auth_code
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(f"{auth_url}/oauth2/token", data=data, headers=headers,
                          auth=(cognito_id, cognito_secret))
        payload = r.json()
        return payload['access_token'], payload['refresh_token']

    def _spend_refresh_token(refresh_token: str) -> str:
        """
        Spends a refresh token to get a fresh access token.

        Parameters
        ----------
        refresh_token
            The refresh token.

        Returns
        -------
        str
            The access token.
        """
        cognito_id = current_app.config["JWT_COGNITO_ID"]
        cognito_secret = current_app.config["JWT_COGNITO_SECRET"]
        auth_url = current_app.config["JWT_COGNITO_URL"]
        data = {
            'grant_type': 'refresh_token',
            'client_id': cognito_id,
            'refresh_token': refresh_token
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(f"{auth_url}/oauth2/token", data=data, headers=headers,
                          auth=(cognito_id, cognito_secret))
        payload = r.json()
        return payload['access_token']

    def login(self, success: callable, failure: callable) -> ResponseType:
        """
        Starts the oauth process when the user chooses to login.
        This will redirect to the Cognito login URL and attempt
        to verify the user using Cognito. If successful, the JWT
        library will store the access and refresh tokens as cookies.

        Parameters
        ----------
        success
            Called on successful login after tokens have been stored.
            Should return some form of Response.
        failure
            Called on failure to verify user. Should return some form
            of response.

        Returns
        -------
        ResponseType
        """
        jwt = self.jwt_manager.get_jwt()
        if jwt:
            return success()
        auth_code = request.args.get('code')
        try:
            if auth_code is None:
                return redirect(self._auth_code_url())
            else:
                access_token, refresh_token = self._get_tokens(auth_code)
                response = make_response(redirect(url_for('client.index')))
                set_access_cookies(response, access_token)
                set_refresh_cookies(response, refresh_token)
                return response
        except Exception:
            return failure()

    def logout(self) -> ResponseType:
        """
        Redirects the user back to the Cognito logout URL and unsets
        the token cookies.

        Returns
        -------
        ResponseType
        """
        response = make_response(redirect(self._auth_code_url(logout=True)))
        unset_jwt_cookies(response)
        return response
