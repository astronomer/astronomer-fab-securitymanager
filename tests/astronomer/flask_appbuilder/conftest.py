import uuid

import flask_appbuilder
from jwcrypto import jwk
import pytest
from sqlalchemy import event

from astronomer.flask_appbuilder.security import AstroSecurityManagerMixin


@pytest.fixture(scope='module')
def app():
    from flask import Flask
    app = Flask(__name__)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_RECORD_QUERIES'] = True
    app.config['SECRET_KEY'] = 'thisismyscretkey'
    app.config['TESTING'] = True

    @app.route("/")
    def home():
        return "Hello"
    return app


@pytest.fixture(scope='module')
def db(app, sm_class):
    from flask_appbuilder import SQLA
    print("New db")
    return SQLA(app)


@pytest.fixture(scope='module')
def appbuilder(app, db, sm_class):
    from flask_appbuilder import AppBuilder

    appbuilder = AppBuilder(app, db.session, security_manager_class=sm_class)

    for r in ('Admin', 'Op', 'User', 'Viewer'):
        appbuilder.sm.add_role(r)

    """
    from sqlalchemy import event
    @event.listens_for(db.engine, 'before_cursor_execute')
    def before_cursor_execute(conn, cursor, statement, parameters,
                              context, executemany):
        print("%s %r", statement, parameters)

    @event.listens_for(db.engine, 'begin')
    def begin(conn):
        print("BEGIN")

    @event.listens_for(db.engine, 'commit')
    def commit(conn):
        __import__('ipdb').set_trace()
        print("COMMIT")

    @event.listens_for(db.engine, 'rollback')
    def rb(conn):
        print("ROLLBACK")

    """
    return appbuilder


@pytest.fixture
def run_in_transaction(appbuilder, db, request):
    """
    Run each test in an isolated transation that is rolledback.

    Since the AppBuilder creation is relatively expensive (It creates a lot of
    objects, and permissions rows etc) we don't want to start _each test_ with
    a totally fresh DB. But we do want DB isolation for each test. So we use a
    (nested) transaction so we can roll it back.
    """

    txn = appbuilder.session.begin_nested()
    txn2 = appbuilder.session.begin_nested()  # noqa

    @event.listens_for(db.engine, 'commit')
    def commit(conn):
        # We don't mind if the nested transaction is "commited" (i.e. the savepoint
        # has been released) so long as we never issue a COMMIT instruction
        raise RuntimeError("TestLogicError: Transaction was unexpectely commited!")

    yield appbuilder
    txn.rollback()
    pass


@pytest.fixture(scope='module')
def sm_class(jwt_signing_key, allowed_audience):
    class SM(AstroSecurityManagerMixin, flask_appbuilder.security.sqla.manager.SecurityManager):
        def count_users(self):
            # Silence the log message about no users
            return 1

    # AppBuilder needs a function that accepts a single argument (the AppBuilder instance)
    return lambda appbuilder: SM(appbuilder, jwt_signing_key, allowed_audience)


@pytest.fixture(scope='session')
def jwt_signing_key():
    return jwk.JWK(generate='oct', size=256)


@pytest.fixture(scope='session')
def jwt_signing_keypair():
    # Create a small key for quicker tests
    return jwk.JWK.generate(kty='RSA', size=512)


@pytest.fixture
def jwt_signing_cert(tmp_path, jwt_signing_keypair):
    """
    Write the certificate to a PEM file in a per-test temp directory
    """
    pem = tmp_path / 'tls.crt'
    pem.write_bytes(jwt_signing_keypair.export_to_pem())
    return str(pem)


@pytest.fixture
def user(appbuilder, valid_claims, role):
    username = str(uuid.uuid4())
    email = 'airflower@domain.com'

    txn2 = appbuilder.session.begin_nested()
    if not appbuilder.sm.add_user(username, 'Lucy', 'Airflower', email, role('Admin')):
        raise RuntimeError("Error creating test user")
    if txn2.is_active:
        # add_user calls commit(), but lets be safe and ensure it does
        txn2.commit()
    user = appbuilder.sm.find_user(username=username)

    return user


@pytest.fixture
def role(appbuilder):
    def role_factory(role):
        # add_role commits. We don't want that
        txn = appbuilder.session.begin_nested()
        role = appbuilder.sm.add_role(role)
        if txn.is_active:
            txn.commit()

        return role

    return role_factory
