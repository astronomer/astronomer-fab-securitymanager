from unittest.mock import MagicMock, patch

from flask import url_for
import pytest


@pytest.mark.usefixtures("client_class", "run_in_transaction")
class TestCurrentUserBackend:
    def test_allow_current_user(
        self, signed_jwt, valid_claims
    ):
        jwt = signed_jwt(valid_claims)
        resp = self.client.get(
            url_for("home"), headers=[("Authorization", "Bearer " + jwt)]
        )
        assert resp.status_code == 200

    @patch("astronomer.flask_appbuilder.security.login_user")
    def test_reject_anonymous_user(
        self, login_user, signed_jwt, valid_claims
    ):
        login_user = MagicMock()
        login_user.return_value = True

        jwt = signed_jwt(valid_claims)
        resp = self.client.get(
            url_for("home"), headers=[("Authorization", "Bearer " + jwt)]
        )
        assert resp.status_code == 401
