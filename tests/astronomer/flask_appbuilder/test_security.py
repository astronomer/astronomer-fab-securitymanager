import os
import time
from unittest.mock import ANY, MagicMock, patch

from flask import g, url_for
import pytest
from tests.astronomer.flask_appbuilder.conftest import AUDIENCE

from astronomer.flask_appbuilder.security import AirflowAstroSecurityManager, timed_lru_cache


@pytest.mark.usefixtures('run_in_transaction', 'airflow_config')
class TestAirflowAstroSecurityManger:
    def test_default_config(self, appbuilder, jwt_signing_keypair, allowed_audience):
        sm = AirflowAstroSecurityManager(appbuilder)

        assert sm.allowed_audience == allowed_audience
        assert sm.jwt_signing_cert.thumbprint() == jwt_signing_keypair.thumbprint()
        assert sm.validity_leeway == 60

    @pytest.mark.parametrize("leeway", [0, 120])
    def test_leeway(self, appbuilder, monkeypatch, leeway):
        monkeypatch.setitem(os.environ, 'AIRFLOW__ASTRONOMER__JWT_VALIDITY_LEEWAY', str(leeway))
        sm = AirflowAstroSecurityManager(appbuilder)

        assert sm.validity_leeway == leeway

    @patch("astronomer.flask_appbuilder.security.urlopen")
    def test_reload_jwt_signing_cert_valid_key(
        self, mock_urlopen, appbuilder, monkeypatch
    ):
        mock = MagicMock()
        mock.getcode.return_value = 200
        mock.read.return_value = b"""
{
  "kty":"EC",
  "crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "kid":"Public key used in JWS spec Appendix A.3 example"
}
"""
        mock.__enter__.return_value = mock
        mock_urlopen.return_value = mock
        monkeypatch.setitem(
            os.environ,
            "AIRFLOW__ASTRONOMER__HOUSTON_JWK_URL",
            "http://houston-astronomer:8871/v1/.well-known/jwks.json",
        )
        # let's make it fallback to ask houston jwk houston api
        monkeypatch.setitem(
            os.environ, "AIRFLOW__ASTRONOMER__JWT_SIGNING_CERT", "/nonexisting"
        )
        AirflowAstroSecurityManager(appbuilder)
        mock_urlopen.assert_called_once()

    @pytest.mark.parametrize(
        "timeout, expected_timeout",
        [
            (None, 10.0),
            (60, 60),
            (5.0, 5.0),
        ]
    )
    @patch("astronomer.flask_appbuilder.security.jwk.JWK.from_json")
    @patch("astronomer.flask_appbuilder.security.urlopen")
    def test_timeout_is_correctly_set(
        self, mock_urlopen, mock_jwt_json, timeout, expected_timeout, appbuilder, monkeypatch
    ):
        monkeypatch.setitem(
            os.environ,
            "AIRFLOW__ASTRONOMER__HOUSTON_JWK_URL",
            "http://houston-astronomer:8871/v1/.well-known/jwks.json",
        )
        if timeout is not None:
            monkeypatch.setitem(
                os.environ,
                "AIRFLOW__ASTRONOMER__HOUSTON_URL_TIMEOUT",
                str(timeout),
            )
        AirflowAstroSecurityManager(appbuilder)
        mock_urlopen.assert_called_once_with(ANY, timeout=expected_timeout)


@pytest.mark.usefixtures('client_class', 'run_in_transaction')
class TestAstroSecurityManagerMixin:

    def test_no_auth(self, appbuilder):
        resp = self.client.get(appbuilder.get_url_for_userinfo)
        assert resp.status_code == 403

    def test_invalid_jwt(self, appbuilder, invalid_jwt):
        resp = self.client.get(appbuilder.get_url_for_userinfo, headers=[('Authorization', 'Bearer ' + invalid_jwt)])
        assert resp.status_code == 403

    @pytest.mark.parametrize("claims", [
        {'made_up_claim': 'admin'},
        {'email': None, 'roles': None},
        {'email': None, 'roles': None, 'sub': None, 'full_name': None, 'aud': AUDIENCE},
        {'email': None,
         'roles': None,
         'sub': None,
         'full_name': None,
         'aud': AUDIENCE},
        {'email': 'airflow@domain.com',
         'roles': None,
         'sub': 'airflow@domain.com',
         'full_name': None,
         'aud': AUDIENCE},
        {'email': 'airflow@domain.com',
         'sub': 'airflow@domain.com',
         'full_name': None,
         'roles': 'NotAList',
         'aud': AUDIENCE},
    ])
    def test_signed_jwt_invalid_claims(self, appbuilder, signed_jwt, claims):
        jwt = signed_jwt(claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 403

    def test_signed_jwt_valid_claims_new_user(self, appbuilder, signed_jwt, valid_claims):
        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 200
        assert g.user.is_anonymous is False
        assert ['Op'] == [r.name for r in g.user.roles]

        assert appbuilder.sm.find_user(username=valid_claims['sub']) == g.user

        # Ensure that we actually wrote to the DB
        appbuilder.session.refresh(g.user)

    def test_signed_jwt_valid_claims_existing_user(self, appbuilder, user, signed_jwt, valid_claims, mocker):
        # Testing of role behaviour is checked via test_manage_user_roles
        mocker.patch.object(appbuilder.sm, 'manage_user_roles')

        valid_claims['full_name'] = 'John McAirflower'
        valid_claims['sub'] = user.username

        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 200
        assert g.user.is_anonymous is False
        appbuilder.sm.manage_user_roles.assert_called_with(mocker.ANY, valid_claims['roles'])

        appbuilder.session.refresh(g.user)
        assert g.user.first_name == 'John McAirflower'

    def test_signed_jwt_misaligned_roles(self, appbuilder, user, signed_jwt, valid_claims, mocker):
        # Testing that when a misalignement between astronomer and the flask session is detected the user is logged out and redirected
        mocker.patch.object(appbuilder.sm, 'manage_user_roles')

        # sign in the user with admin role claims
        valid_claims['full_name'] = 'John McAirflower'
        valid_claims['sub'] = user.username
        valid_claims['roles'] = ["Admin"]
        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 200
        assert g.user.is_anonymous is False
        appbuilder.sm.manage_user_roles.assert_called_with(mocker.ANY, valid_claims['roles'])

        # Using same flask session navigate to home with Viewer role claims
        appbuilder.session.refresh(g.user)
        assert g.user.first_name == 'John McAirflower'
        valid_claims['roles'] = ["Viewer"]
        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 302
        assert g.user.is_anonymous is True

    def test_manage_user_roles__manage_all(self, appbuilder, role, user):
        """
        When sm.roles_to_manage is None (the default) then the complete list of
        roles passed in should be what the user will be a member of
        """
        sm = appbuilder.sm

        user.roles.append(role('Other'))
        user.roles.append(role('Viewer'))
        sm.manage_user_roles(user, ['Admin', 'User'])

        assert {r.name for r in user.roles} == {'Admin', 'User'}

    def test_manage_user_roles__manage_subset(self, appbuilder, user, role, monkeypatch):
        """
        When sm.roles_to_manage is a non-empty set then any role that is not in that
        list should be left
        """
        sm = appbuilder.sm

        monkeypatch.setattr(sm, 'roles_to_manage', {'Admin', 'Viewer', 'Op', 'User'})
        user.roles.append(role('Other'))
        user.roles.append(role('Viewer'))

        sm.manage_user_roles(user, ['Admin', 'User'])

        assert {r.name for r in user.roles} == {'Admin', 'User', 'Other'}

    @pytest.mark.parametrize("leeway", [0, 60])
    def test_expired(self, appbuilder, signed_jwt, valid_claims, monkeypatch, leeway):
        monkeypatch.setattr(appbuilder.sm, 'validity_leeway', leeway)
        valid_claims['exp'] = int(time.time()) - leeway - 1

        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 403

    @pytest.mark.parametrize("leeway", [0, 60])
    def test_not_yet_valid(self, appbuilder, signed_jwt, valid_claims, monkeypatch, leeway):
        monkeypatch.setattr(appbuilder.sm, 'validity_leeway', leeway)
        valid_claims['nbf'] = int(time.time()) + leeway + 10

        jwt = signed_jwt(valid_claims)
        resp = self.client.get(url_for('home'), headers=[('Authorization', 'Bearer ' + jwt)])
        assert resp.status_code == 403

    def test_has_access_to_user_create(self, appbuilder, user):

        with appbuilder.app.test_request_context() as context:
            g.user = user
            context.user = user

            sm = appbuilder.sm
            assert sm.has_access('can_create', 'Users') is False
            assert sm.has_access('can_read', 'Website') is True


class TestCache():
    def test_lru_cache_time_one_second(self):
        @timed_lru_cache(seconds=1, maxsize=1)
        def foo(x):
            return x
        assert foo(42) == 42
        time.sleep(0.25)
        assert foo(42) == 42
        time.sleep(1)
        assert foo(43) == 43
