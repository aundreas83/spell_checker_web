import pytest
from app.models import User
from app import app

def test_new_user(new_user):
    assert new_user.username == 'pytest'
    assert new_user.password_hash != '1234'
    assert new_user.twofactorauth != '12345'
    assert not new_user.authenticated

def test_home_page(test_client):
    response = test_client.get("/")
    assert response.status_code == 302

def test_login_page(test_client):
    response = test_client.get("/login")
    assert response.status_code == 200
    assert b"Login" in response.data
    assert b"Username" in response.data

def test_login(test_client):
    response = test_client.post("/login", 
        data=dict(username="danny", password="p@ssw0rd", twofactorauth="4055035595"),
        follow_redirects=True)
    assert b"success" in response.data

def test_registration_page(test_client):
    response = test_client.get("/register")
    assert response.status_code == 200
    assert b"Register" in response.data
    assert b"Username" in response.data
    assert b"2fa" in response.data


def test_registration(test_client):
    response = test_client.post("/register",
        data=dict(username="danny", password="p@ssw0rd", twofactorauth="4055035595"),
        follow_redirects=True)
    assert b"success" in response.data



