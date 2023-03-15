# Copyright 2019 Astronomer Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import datetime
import functools
import json
from logging import getLogger
import os
from time import monotonic_ns
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import airflow
from airflow.exceptions import AirflowConfigException
from flask import abort, flash, redirect, request, session, url_for
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.views import AuthView, expose
from flask_login import current_user, login_user, logout_user
from jwcrypto import jwk, jws, jwt
from packaging.version import Version

try:
    from airflow.www_rbac.security import (EXISTING_ROLES,
                                           AirflowSecurityManager)
except ImportError:
    try:
        from airflow.www.security import EXISTING_ROLES, AirflowSecurityManager
    except ImportError:
        # Airflow not installed, likely we are running setup.py to _install_ things
        class AirflowSecurityManager(object):
            def __init__(self, appbuilder):
                pass
        EXISTING_ROLES = []


__version__ = "1.9.4"

log = getLogger(__name__)

AIRFLOW_VERSION_TUPLE = Version(airflow.__version__).release


def timed_lru_cache(
    _func=None, *, seconds=300, maxsize=1, typed=False
):
    """
    Extension of functools lru_cache with a timeout
    seconds (int): Timeout in seconds to clear the WHOLE cache, default = 5 minutes
    maxsize (int): Maximum Size of the Cache
    typed (bool): Same value of different type will be a different entry
    """

    def wrapper_cache(f):
        f = functools.lru_cache(maxsize=maxsize, typed=typed)(f)
        f.delta = seconds * 10 ** 9
        f.expiration = monotonic_ns() + f.delta

        @functools.wraps(f)
        def wrapped_f(*args, **kwargs):
            if monotonic_ns() >= f.expiration:
                f.cache_clear()
                f.expiration = monotonic_ns() + f.delta
            return f(*args, **kwargs)

        wrapped_f.cache_info = f.cache_info
        wrapped_f.cache_clear = f.cache_clear
        return wrapped_f

    # To allow decorator to be used without arguments
    if _func is None:
        return wrapper_cache
    else:
        return wrapper_cache(_func)


class AstroSecurityManagerMixin(object):
    """
    Flask-AppBuilder SecurityManager mix in that auto-creates users based on
    the signed JWT token from the Astronomer platform

    For this security manager to function the ``AUTH_TYPE`` in your FAB
    application's config must be set to
    ``AUTH_REMOTE_USER``:

    .. code:: python

        from flask_appbuilder.security.manager import AUTH_REMOTE_USER
        AUTH_TYPE = AUTH_REMOTE_USER

    **Required JWT token claims**

    We require the following claims in the token:

    ``sub``
        Subject. The User ID/username. This is used to find the user record
    ``aud``
        Audience. What "domain" this token is for. List of strings or string.
        The value of "allowed_audience" must appear in this list
    ``exp``
        Token expiry. Integer seconds since 1970 epoch.
    ``nbf``
        "Not Before". Earliest time at which token is valid. Integer seconds since 1970 epoch.
    ``email``
        User's email address.
    ``full_name``
        Must be present, but can be null, in which case ``email`` user's name
        will be set to email. This field is what FAB displays in the UI.
    ``roles``
        An array of role names that the user should be in. See :meth:`manage_user_roles`.


    :param appbuilder:
    :type appbuilder: flask_appbuilder.AppBuilder
    :param jwt_signing_cert: JsonWebKey that must have signed the token. Can be
        a public key, or a base64-encoded shared secret. See
        :class:`jwcrypto.jwk.JWK` for more info.
    :type jwt_signing_cert: jwcrypto.jwk.JWK
    :param allowed_audience: Valiid ``aud`` claims to accept
    :type allowed_audience: list[str] or str
    :param validity_leeway: Number of seconds past token expiry to accept. Default 60
    :type validity_leeway: int
    :param roles_to_manage: List of roles to manage. See
        :meth:`manage_user_roles` for behaviour of this parameter
    :type roles_to_manage: list[str] or None
    """
    def __init__(self, appbuilder, jwt_signing_cert, allowed_audience, roles_to_manage=None, validity_leeway=60):
        super().__init__(appbuilder)
        if self.auth_type == AUTH_REMOTE_USER:
            self.authremoteuserview = AuthAstroJWTView
        self.jwt_signing_cert = jwt_signing_cert
        self.allowed_audience = allowed_audience
        self.roles_to_manage = roles_to_manage
        self.validity_leeway = validity_leeway

    def before_request(self):
        """
        Validate  the JWT token provider in the ``Authorization`` HTTP header
        and log in the user.

        There is no separate Log In view for this SecurityManager - it is
        implicit on the first request.

        The value of this header is required to be a ``Bearer <token>``. If
        this header is missing or the token is invalid for any reason a 403
        response will be returned.

        The token will be validated on every request, but the database will
        only be updated if the current session is anonymous.

        If a user with a username of the ``sub`` claim can be found it will be
        updated to match the claims. Otherwise a new user record will be
        created.
        """
        if request.path == '/health':
            return super().before_request()

        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return abort(403)

        if not auth_header.startswith('Bearer '):
            return abort(403)

        try:
            token = jwt.JWT(
                check_claims={
                    # These must be present - any value
                    'sub': None,
                    'email': None,
                    'full_name': None,
                    'roles': None,

                    # Use it's built in handling - 60s leeway, 10minutes validity.
                    'exp': None,
                    'nbf': None,

                    # This must match exactly
                    'aud': self.allowed_audience,
                }
            )

            token.leeway = self.validity_leeway

            token.deserialize(jwt=auth_header[7:], key=self.jwt_signing_cert)
            claims = json.loads(token.claims)
        except jws.InvalidJWSSignature:
            abort(403)
        except jwt.JWException as e:
            log.debug(e)
            abort(403)

        if not isinstance(claims['roles'], list):
            abort(403)

        if current_user.is_anonymous:
            user = self.find_user(username=claims['sub'])
            if user is None:
                log.info('Creating airflow user details for %s from JWT', claims['email'])
                user = self.user_model(
                    # All we have is REMOTE_USER, so we set
                    # the other fields to blank.
                    username=claims['sub'],
                    first_name=claims['full_name'] or claims['email'],
                    last_name=' ',
                    email=claims['email'],
                    roles=[self.find_role(role) for role in claims['roles']],
                    active=True
                )
            else:
                log.info('Updating airflow user details for %s from JWT', claims['email'])
                # Update details from JWT
                user.username = claims['sub']
                user.first_name = claims['full_name'] or claims['email']
                user.last_name = ' '
                user.active = True
                self.manage_user_roles(user, claims['roles'])

            # Similar to the upstream FAB security managers, update
            # authentication stats so user admins can view them without
            # having to dig through webserver logs
            if not user.login_count:
                user.login_count = 0
            user.login_count += 1
            user.last_login = datetime.datetime.now()
            user.fail_login_count = 0

            self.get_session.add(user)
            self.get_session.commit()
            if not login_user(user):
                raise RuntimeError("Error logging user in!")
            session["roles"] = claims['roles']
        else:
            session_roles = session['roles']
            claim_roles = claims['roles']
            if set(session_roles) != set(claim_roles):
                logout_user()
                flash('Your permission set has changed. You have been redirected to the Airflow homepage with your new permission set.')
                return redirect(url_for('IndexView.index'))

        super().before_request()

    def manage_user_roles(self, user, roles):
        """
        Manage the core roles on the user

        If ``self.roles_to_manage`` is an empty list or None, then the user
        will only be in the roles passed via the ``roles`` parameter.

        Otherwise any role that the user is a member of that is not in the
        ``self.roles_to_manage`` list will remain.
        """
        desired = set(roles)

        if self.roles_to_manage:
            roles_to_remove = self.roles_to_manage - desired
        else:
            # Every role that isn't in `roles` should be removed from this
            # user
            roles_to_remove = {r.name for r in user.roles} - desired

        # Capture it in a variable - otherwise it changes underneath us as we
        # iterate and we miss some
        current_roles = list(user.roles)

        for role in current_roles:
            if role.name in roles_to_remove:
                user.roles.remove(role)
            elif role.name in desired:
                desired.remove(role.name)

        # Anything left in desired is a role we need to add
        for role in desired:
            user.roles.append(self.find_role(role))

    try:
        # Python binding/closures are acting weird. Without this, the useage in `has_access` below can't
        # find permissions!
        global permissions
        import airflow.security.permissions

        # Don't let anyone create users when this Security Manager is in use -- it creates them on demand.
        # Check they exist
        permissions = airflow.security.permissions
        permissions.RESOURCE_USER
        permissions.ACTION_CAN_CREATE

        def has_access(self, action_name, resource_name, *args, **kwargs) -> bool:
            if action_name == permissions.ACTION_CAN_CREATE and resource_name == permissions.RESOURCE_USER:
                return False
            return super().has_access(action_name, resource_name,  *args, **kwargs)

    except (ImportError, AttributeError):
        pass


Airflow23CompatibilityMixin = object
# Only define this if we're using an old version of Airflow
if AIRFLOW_VERSION_TUPLE < (2, 3):
    class Airflow23CompatibilityMixin:
        # We only define the methods that we use
        #
        # See https://github.com/apache/airflow/commit/6deebec04c71373f5f99a14a3477fc4d6dc9bcdc
        # for the mapping
        #
        # If we need any other methods, rescue them from:
        # https://github.com/apache/airflow/blob/86a2a19ad2bdc87a9ad14bb7fde9313b2d7489bb/airflow/www/security.py#L242
        def get_permission(self, action_name, resource_name):
            """
            Gets a permission made with the given action->resource pair, if the permission already exists.
            :param action_name: Name of action
            :type action_name: str
            :param resource_name: Name of resource
            :type resource_name: str
            :return: The existing permission
            :rtype: PermissionView
            """
            return self.find_permission_view_menu(action_name, resource_name)

        def add_permission_to_role(self, role, permission):
            """
            Add an existing permission pair to a role.
            :param role: The role about to get a new permission.
            :type role: Role
            :param permission: The permission pair to add to a role.
            :type permission: PermissionView
            :return: None
            :rtype: None
            """
            self.add_permission_role(role, permission)


class AirflowAstroSecurityManager(AstroSecurityManagerMixin, AirflowSecurityManager, Airflow23CompatibilityMixin):
    """
    This class configures the FAB SecurityManager for use in Airflow, and reads
    settings under the ``[astronomer]`` section (or environment variables prefixed
    with ``AIRFLOW__ASTRONOMER__``).

    This class will only manage the "core" roles built in to Airflow
    (Admin, Op, User, Viewer, Public) are correct for the given user - if a
    user is added to any custom roles the membership of those will not be
    removed.

    **Required Airflow Config settings:**


    ``astronmer.jwt_signing_cert``
        Path to a public key file containing the public key, in PEM format,
        that is trusted to sign JWT tokens
    ``astronomer.jwt_audience``
        The audience value to accept in JWT tokens. This should be the hostname
        of this Airflow deployment

    **Optioinal config settings:**

    ``astronomer.jwt_validity_leeway``
        Override the default leeway on validating token expiry time

    """
    def __init__(self, appbuilder):
        from airflow.configuration import conf
        from airflow.exceptions import AirflowConfigException

        self.jwt_signing_cert_mtime = 0

        self.jwt_signing_cert_path = conf.get('astronomer', 'jwt_signing_cert')
        self.reload_jwt_signing_cert()

        allowed_audience = conf.get('astronomer', 'jwt_audience')

        kwargs = {
            'appbuilder': appbuilder,
            'jwt_signing_cert': self.jwt_signing_cert,
            'allowed_audience': allowed_audience,
            'roles_to_manage': EXISTING_ROLES,
        }

        # Airflow 1.10.2 doesn't have `fallback` support yet
        try:
            leeway = conf.get('astronomer', 'jwt_validity_leeway', fallback=None)
            if leeway is not None:
                kwargs['validity_leeway'] = int(leeway)
        except AirflowConfigException:
            pass

        super().__init__(**kwargs)

    def reload_jwt_signing_cert(self):
        """
        Reload (or load) the JWT signing cert from disk if the file has been modified.
        """
        try:
            self.jwt_signing_cert = self._get_jwt_key_from_houston()
            if self.jwt_signing_cert:
                return
        except (AirflowConfigException, HTTPError, URLError):
            pass
        stat = os.stat(self.jwt_signing_cert_path)
        if stat.st_mtime_ns > self.jwt_signing_cert_mtime:
            log.info(
                "Loading Astronomer JWT signing cert from %s",
                self.jwt_signing_cert_path,
            )
            with open(self.jwt_signing_cert_path, "rb") as fh:
                self.jwt_signing_cert = jwk.JWK.from_pem(fh.read())
                # This does a second stat, but only when changed, and ensures
                # that the time we record matches _exactly_ the time of the
                # file we opened.
                self.jwt_signing_cert_mtime = os.fstat(fh.fileno()).st_mtime_ns

    @timed_lru_cache
    def _get_jwt_key_from_houston(self):
        from airflow.configuration import conf

        # Example: http://houston-astronomer:8871/v1/.well-known/jwks.json
        houston_url = conf.get("astronomer", "houston_jwk_url", fallback=None)
        if not houston_url:
            return None
        log.info("Loading Astronomer JWT from houston jwk")
        httprequest = Request(
            houston_url, method="GET", headers={"Accept": "application/json"}
        )
        houston_url_timeout = conf.getfloat("astronomer", "houston_url_timeout", fallback=10.0)
        with urlopen(httprequest, timeout=houston_url_timeout) as response:
            key = response.read().decode()
        return jwk.JWK.from_json(key=key)

    def before_request(self):
        # To avoid making lots of stat requests don't do this for static
        # assets, just Airflow pages and API endpoints
        if not request.path.startswith("/static/"):
            self.reload_jwt_signing_cert()
        return super().before_request()

    def sync_roles(self):
        super().sync_roles()

        for (view_menu, permission) in [
                ('UserDBModelView', 'can_userinfo'),
                ('UserDBModelView', 'userinfoedit'),
                ('UserRemoteUserModelView', 'can_userinfo'),
                ('UserRemoteUserModelView', 'userinfoedit'),
                ('UserInfoEditView', 'can_this_form_get'),
                ('UserInfoEditView', 'can_this_form_post'),
        ]:
            perm = self.get_permission(permission, view_menu)
            # If we are only using the RemoteUser auth type, then the DB permissions won't exist. Just continue
            if not perm:
                continue

            self.add_permission_to_role(self.find_role("User"), perm)
            self.add_permission_to_role(self.find_role("Op"), perm)
            self.add_permission_to_role(self.find_role("Viewer"), perm)

        for (view_menu, permission) in [
                ('Airflow', 'can_dagrun_success'),
                ('Airflow', 'can_dagrun_failed'),
                ('Airflow', 'can_failed'),
        ]:
            self.add_permission_to_role(self.find_role("User"), self.get_permission(permission, view_menu))
            self.add_permission_to_role(self.find_role("Op"), self.get_permission(permission, view_menu))

        for (view_menu, permission) in [
                ('VariableModelView', 'varexport'),
        ]:
            self.add_permission_to_role(self.find_role("Op"), self.get_permission(permission, view_menu))


class AuthAstroJWTView(AuthView):
    """
    If a user does not have permission, they are automatically rediected
    to the login function of this class. Since we handle everything externally
    we make this look more like an actual 403 error.

    Reference to FAB: https://github.com/dpgaspar/Flask-AppBuilder/blob/fd8e323fcd59ec4b28df91e12915eeebdf293060/flask_appbuilder/security/decorators.py#L134
    """
    @expose("/access-denied/")
    def login(self):
        return abort(403)
