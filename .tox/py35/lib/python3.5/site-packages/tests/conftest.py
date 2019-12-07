import pytest
from app.models import User
from app import app

@pytest.fixture(scope='module')
def new_user():
    app.config["WTF_CSRF_ENABLED"] = False
    user = User('pytest', '1234', '12345')
    return user

@pytest.fixture(scope='module')
def test_client():
    app.config["WTF_CSRF_ENABLED"] = False
    testing_client = app.test_client()
    return testing_client

