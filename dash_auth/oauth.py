from __future__ import absolute_import
import flask
import json
import os
from textwrap import dedent
import itsdangerous
import functools
import urllib
import requests

from .auth import Auth
from . import api_requests


def need_request_context(func):
    @functools.wraps(func)
    def _wrap(*args, **kwargs):
        if not flask.has_request_context():
            raise RuntimeError('`{0}` method needs a flask/dash request'
                               ' context to run. Make sure to run '
                               '`{0}` from a callback.'.format(func.__name__))
        return func(*args, **kwargs)
    return _wrap


class OAuth(Auth):
    # Name of the cookie containing the cached permission token
    AUTH_COOKIE_NAME = 'dash_token'
    # Name of the cookie containing the OAuth2 access token
    TOKEN_COOKIE_NAME = 'oauth_token'
    USERNAME_COOKIE = 'dash_user'
    USERDATA_COOKIE = 'dash_user_data'

    def __init__(
            self,
            app,
            app_url,
            client_id=None,
            secret_key=None,
            salt=None, authorization_hook=None):
        Auth.__init__(self, app, authorization_hook)

        self.config = {
            'permissions_cache_expiry': 5 * 60,
            'user_cookies_expiry': 604800,  # one week.
        }

        self._app = app
        self._app_url = app_url
        self._oauth_client_id = client_id
        self._username_cache = {}

        if secret_key is None and app.server.secret_key is None:
            raise Exception(dedent('''
                app.server.secret_key is missing.
                Generate a secret key in your Python session
                with the following commands:

                >>> import os
                >>> import base64
                >>> base64.b64encode(os.urandom(30)).decode('utf-8')

                and assign it to the property app.server.secret_key
                (where app is your dash app instance).
                Note that you should not do this dynamically:
                you should create a key and then assign the value of
                that key in your code.
            '''))

        if salt is None:
            raise Exception(dedent('''
                salt is missing. The salt parameter needs to a string that
                is unique to this individual Dash app.
            '''))

        self._signer = itsdangerous.TimestampSigner(secret_key, salt=salt)
        self._json_signer = itsdangerous.JSONWebSignatureSerializer(
            secret_key, salt=salt)

        app.server.add_url_rule(
            '{}_dash-login'.format(app.config['routes_pathname_prefix']),
            view_func=self.login_api,
            methods=['post']
        )

        app.server.add_url_rule(
            '{}_oauth-redirect'.format(app.config['routes_pathname_prefix']),
            view_func=self.serve_oauth_redirect,
            methods=['get']
        )

        app.server.add_url_rule(
            '{}_is-authorized'.format(app.config['routes_pathname_prefix']),
            view_func=self.check_if_authorized,
            methods=['get']
        )
        _current_path = os.path.dirname(os.path.abspath(__file__))

        # TODO - Dist files
        with open(os.path.join(_current_path, 'oauth-redirect.js'), 'r') as f:
            self.oauth_redirect_bundle = f.read()

        with open(os.path.join(_current_path, 'login.js'), 'r') as f:
            self.login_bundle = f.read()

        @self.app.server.before_request
        def handle_access_token():
            urlsplit = urllib.parse.urlsplit(flask.request.url)
            params = urllib.parse.parse_qs(urlsplit.query)

            if 'logout' in params:
                return self.logout_api(self.remove_url_query(urlsplit))
            elif 'access_token' in params or 'code' in params:
                return self.login_api(self.remove_url_query(urlsplit), params)

            return None


    def remove_url_query(self, urlsplit):
        urlsplit_list = list(urlsplit)
        urlsplit_list[3] = ''
        return tuple(urlsplit_list)


    def access_token_is_valid(self):
        if self.AUTH_COOKIE_NAME not in flask.request.cookies:
            return False

        access_token = flask.request.cookies[self.AUTH_COOKIE_NAME]

        try:
            self._signer.unsign(
                access_token,
                max_age=self.config['permissions_cache_expiry']
            )
            return True
        except itsdangerous.SignatureExpired:
            # Check access in case the user is valid but the token has expired
            return False
        except itsdangerous.BadSignature:
            # Access tokens in previous versions of `dash-auth`
            # weren't generated with itsdangerous
            # and will raise `BadSignature`
            return False

    def user_data_is_valid(self):
        user = self.get_user_data()
        return user and 'services' in user and 'apps' in user

    def is_authorized(self):
        if self.TOKEN_COOKIE_NAME not in flask.request.cookies:
            return False

        if not self.user_data_is_valid():
            return False
        oauth_token = flask.request.cookies[self.TOKEN_COOKIE_NAME]
        if not self.access_token_is_valid():
            return self.check_view_access(oauth_token)

        return True

    def is_service_authorized(self, services=[]):
        if len(services) == 0:
            return True
        if self.is_authorized():
            user = self.get_user_data()
            if user and 'services' in user:
                for service in services:
                    for user_service in user['services']:
                        if service == user_service:
                            return True
        return False

    def is_app_authorized(self, apps=[]):
        if len(apps) == 0:
            return True
        if self.is_authorized():
            user = self.get_user_data()
            if user and 'apps' in user:
                for app in apps:
                    for user_app in user['apps']:
                        if app == user_app:
                            return True
        return False

    def check_if_authorized(self):
        if self.is_authorized():
            return flask.Response(status=200)

        return flask.Response(status=403)

    def add_access_token_to_response(self, response):
        """
        Add an access token cookie to a response if it doesn't
        already have a valid one. (To be called if auth succeeds to make
        auth "sticky" for other requests.)

        :param (flask.Response|str|unicode) response
        :rtype: (flask.Response)
        """
        try:
            # Python 2
            if isinstance(response, basestring):  # noqa: F821
                response = flask.Response(response)
        except Exception:
            # Python 3
            if isinstance(response, str):
                response = flask.Response(response)

        if not self.access_token_is_valid():
            access_token = self._signer.sign('access')
            self.set_cookie(
                response,
                name=self.AUTH_COOKIE_NAME,
                value=access_token,
                max_age=(60 * 60 * 24 * 7),  # 1 week
            )

            username = self.get_username(validate_max_age=False)
            userdata = self.get_user_data()

            if username:
                self.set_username(username)
            if userdata:
                self.set_user_data(userdata)

        return response

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return self.auth_redirect()

            try:
                response = f(*args, **kwargs)
            except Exception as err:
                # Clear the cookie if auth fail
                if getattr(err, 'status_code', None) in [401, 403]:
                    return self.auth_redirect()
                else:
                    raise

            # TODO - should set secure in this cookie, not exposed in flask
            # TODO - should set path or domain
            return self.add_access_token_to_response(response)
        return wrap

    def auth_redirect(self):
        auth_base_url = api_requests.config('AGRISTA_AUTH_DOMAIN', 'https://staging-id.agrista.com')
        auth_endpoint = api_requests.config('AGRISTA_AUTH_ENDPOINT', '/oauth2/authorize')
        client_id = api_requests.config('AGRISTA_AUTH_CLIENT_ID', '5f59246f-8755-4cb7-8637-147c473acf15')
        params = {
            'client_id': client_id,
            'response_type': 'token',
            'scope': 'profile',
            'redirect_uri': flask.request.url
        }

        return flask.redirect(auth_base_url + auth_endpoint + '?' + urllib.parse.urlencode(params))

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return self.login_request()
        return wrap

    def html(self, script):
        return ('''
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Log In</title>
            </head>
            <body>
              <div id="react-root"></div>
            </body>
            <script id="_auth-config" type="application/json">
            {}
            </script>
            <script type="text/javascript">{}</script>
            </html>
        '''.format(
            json.dumps({
                'oauth_client_id': self._oauth_client_id,
                'requests_pathname_prefix':
                    self._app.config['requests_pathname_prefix']
            }),
            script)
        )

    def login_request(self):
        return self.html(self.login_bundle)

    def serve_oauth_redirect(self):
        return self.html(self.oauth_redirect_bundle)

    def set_cookie(self, response, name, value, max_age, httponly=True, samesite='Lax'):
        response.set_cookie(
            name,
            value=value,
            max_age=max_age,
            secure=True if 'https:' in self._app_url else False,
            path=self._app.config['routes_pathname_prefix'],
            httponly=httponly,
            samesite=samesite
        )

    def clear_cookies(self, response):
        """
        Clear all the auth cookies.

        :param response:
        :type response: flask.Response
        :return:
        """
        for c in (
                self.AUTH_COOKIE_NAME,
                self.TOKEN_COOKIE_NAME,
                self.USERDATA_COOKIE,
                self.USERNAME_COOKIE):
            self._clear_cookie(response, c)

    def _clear_cookie(self, response, cookie_name):
        response.set_cookie(cookie_name,
                            value='',
                            expires=0,
                            secure='https:' in self._app_url)

    def check_view_access(self, oauth_token):
        """Checks the validity of oauth_token."""
        return True

    def login_api(self, split_url, params):
        if 'code' in params:
            code = params.get('code')[0]
            auth_base_url = api_requests.config('AGRISTA_AUTH_DOMAIN', 'https://staging-id.agrista.com')
            token_endpoint = api_requests.config('AGRISTA_TOKEN_ENDPOINT', '/oauth2/token')
            client_id = api_requests.config('AGRISTA_AUTH_CLIENT_ID', '5f59246f-8755-4cb7-8637-147c473acf15')
            client_secret = api_requests.config('AGRISTA_AUTH_CLIENT_SECRET', 'nYmsIJGKbU9ESUXltmOJYTkBnHU7NYBA7xcTU0oi')
            params = {
                'client_id': client_id,
                'client_secret': client_secret,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': flask.request.url
            }

            try:
                res = requests.get(auth_base_url + token_endpoint + '?' + urllib.parse.urlencode(params))
                data = res.json()

                if 'access_token' in data:
                    oauth_token = data['access_token']
                else:
                    raise Exception('Missing access_token')
            except Exception as e:
                print(e)
                raise e
        else:
            oauth_token = params.get('access_token')[0]

        """Obtains the access_token from the URL, sets the cookie."""
        userinfo_base_url = api_requests.config('AGRISTA_USERINFO_DOMAIN', 'https://staging-enterprise.agrista.com')
        headers = {
            'authorization': 'Bearer ' + oauth_token
        }
        try:
            res = requests.get(userinfo_base_url + '/api/me', headers=headers)
        except Exception as e:
            print(e)
            raise e

        data = res.json()
        try:
            data['apps'] = [app['name'] for app in data['userRole']['apps']]
            data['services'] = [app['name'] for app in data['organization']['services']]
            data['organization'].pop('createdAt', None)
            data['organization'].pop('data', None)
            data['organization'].pop('hostUrl', None)
            data['organization'].pop('services', None)
            data['organization'].pop('status', None)
            data.pop('accessLevel', None)
            data.pop('activeDirectory', None)
            data.pop('isActive', None)
            data.pop('isBudgetPublisher', None)
            data.pop('profilePhoto', None)
            data.pop('status', None)
            data.pop('teams', None)
            data.pop('userRole', None)
        except Exception as e:
            print(e)
        response = flask.redirect(urllib.parse.urlunsplit(split_url))

        self.set_username(data.get('email'))
        self.set_user_data(data)
        self.set_cookie(
            response=response,
            name=self.TOKEN_COOKIE_NAME,
            value=oauth_token,
            max_age=None
        )

        return response

    def logout_api(self, split_url):
        response = flask.redirect(urllib.parse.urlunsplit(split_url))
        response.delete_cookie(self.USERNAME_COOKIE)
        response.delete_cookie(self.USERDATA_COOKIE)
        response.delete_cookie(self.TOKEN_COOKIE_NAME)

        return response

    @need_request_context
    def get_username(self, validate_max_age=True):
        """
        Retrieve the username from the `dash_user` cookie.

        :return: The stored username if any.
        :rtype: str
        """
        cached = self._username_cache.get(flask.request.remote_addr)
        if cached:
            return cached
        username = flask.request.cookies.get(self.USERNAME_COOKIE)
        if username:
            max_age = None
            if validate_max_age:
                max_age = self.config['permissions_cache_expiry']
            unsigned = self._signer.unsign(username, max_age=max_age)
            return unsigned.decode('utf-8')

    @need_request_context
    def get_user_data(self):
        """
        Retrieve the user data from `dash_user_data` cookie.

        :return: The stored user data if any.
        :rtype: dict
        """

        user_data = flask.request.cookies.get(self.USERDATA_COOKIE)
        if user_data:
            return self._json_signer.loads(user_data)

    @need_request_context
    def set_username(self, name):
        """
        Store the username in the `dash_user` cookie.

        :param name: the name of the user.
        :type name: str
        :return:
        """
        self._username_cache[flask.request.remote_addr] = name

        @flask.after_this_request
        def _set_username(response):
            self.set_cookie(
                response,
                self.USERNAME_COOKIE,
                self._signer.sign(name),
                max_age=self.config['user_cookies_expiry'])
            del self._username_cache[flask.request.remote_addr]
            return response

    @need_request_context
    def set_user_data(self, data):
        """
        Set meta data for a user to store in a cookie.

        :param data: Data to encode and store.
        :type data: dict, list
        :return:
        """

        @flask.after_this_request
        def _set_data(response):
            self.set_cookie(
                response,
                self.USERDATA_COOKIE,
                self._json_signer.dumps(data),
                max_age=self.config['user_cookies_expiry'])
            return response
