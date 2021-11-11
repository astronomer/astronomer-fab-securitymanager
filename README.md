# astronomer-fab-securitymanager

A custom Flask-AppBuilder security manager for use with [Apache
Airflow][Airflow] inside the [Astronomer Platform].

This [Security Manager] will validate the JWT tokens from the Astronomer
platform and automatically create or update the user record as appropriate.

It looks at the `roles` claim of the validated JWT token and ensures the user
has those roles. If the user already exists it will remove any extra roles from
the "stock" roles (currently Admin, Op, User, and Viewer) - but will leave any
custom roles alone. (There is no support for assigning users to custom Airflow
roles in the Astronomer platform at the moment, so this behaviour might change
in the future)

## Usage

Airflow provides a hook in the `webserver_config.py` file where you can specify
a security manager class. In `webserver_config.py` (in AIRFLOW_HOME,
`~/airflow/` by default) import the class and set

```python
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from astronomer.flask_appbuilder.security import AirflowAstroSecurityManager

# ...

AUTH_TYPE = AUTH_REMOTE_USER
...
SECURITY_MANAGER_CLASS = AirflowAstroSecurityManager
```

This file won't exist until you've run the Airflow webserver at least once in RBAC mode:

```
AIRFLOW__WEBSERVER__RBAC=true airflow webserver --help
```

will ensure that this file exists to edit it.


## Settings

This class uses Airflow's config mechanism under the `astronomer` section. The
easiest way of setting this is via environment variables prefixed with
`AIRFLOW__ASTRONOMER__`

For a list of current settings check out the inline documentation in
[security.py](astronomer/flask_appbuilder/security.py)

## Development

To run tests with coverage:
```
pytest --cov=src --cov-report term-missing
```

Copyright © 2019-2020 Astronomer Inc. See [LICENSE](./LICENSE) for further details.

[Airflow]: https://airflow.apache.org/
[Security Manager]: https://flask-appbuilder.readthedocs.io/en/latest/security.html#your-custom-security
[Astronomer Platform]: https://www.astronomer.io/
