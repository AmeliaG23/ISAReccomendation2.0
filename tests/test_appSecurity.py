"""
File : test_appSecurity.py
Author : Amelia Goldsby
Date Created : 12/05/2024
Project : ISA Recommendation Website
Course : Software Engineering and DevOps
         Level 6, QA 

Description : This test file contains security-focused unit tests for the ISA Recommendation Website.
               Using Pytest, it verifies protection against common OWASP vulnerabilities, including:
               - Broken Access Control
               - Broken Authentication
               - Injection
               - Security Misconfiguration
               - Cross-Site Scripting (XSS)
                (Pytest, 2025).
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app import app, db, User, hashPassword, checkPassword, validateUsername, validatePassword
from flask import session

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

# A01: Broken Access Control - Regular user should not access admin page
def test_regular_user_access_to_admin(client):
    hashed = hashPassword("Test@123")
    user = User(username="normaluser", password=hashed, admin=False)
    with app.app_context():
        db.session.add(user)
        db.session.commit()

        # Re-query user to make sure it is part of the session
        user = db.session.get(User, user.id)

    with client.session_transaction() as sess:
        sess['userId'] = user.id  # Set the userId in the session
        sess['admin'] = False  # Regular user, not admin

    response = client.get('/admin', follow_redirects=True)
    assert b"Invalid credentials" in response.data or b"login" in response.data  # Should block access

# A01: Broken Access Control - Admin user should be able to access admin panel
def test_admin_access_control(client):
    hashed = hashPassword("Admin@123")
    admin_user = User(username="adminuser", password=hashed, admin=True)
    reg_user = User(username="normaluser", password=hashed, admin=False)

    with app.app_context():
        db.create_all()
        db.session.add_all([admin_user, reg_user])
        db.session.commit()
        admin_id = admin_user.id
        reg_id = reg_user.id

    # Admin login
    with client.session_transaction() as sess:
        sess['userId'] = admin_id
        sess['admin'] = True

    response = client.get('/admin', follow_redirects=True)
    assert response.status_code == 200
    assert b"Admin Control" in response.data  # ✅ Confirm admin page loaded properly

    # Regular user login
    with client.session_transaction() as sess:
        sess['userId'] = reg_id
        sess['admin'] = False

    response = client.get('/admin', follow_redirects=True)
    assert b"Invalid credentials" in response.data or b"login" in response.data


# A02: Broken Authentication - Test if passwords are securely hashed and can't be easily cracked
def test_password_is_hashed_and_secure():
    password = "Secure@123"
    hashed = hashPassword(password)
    assert hashed != password  # Password should not match hash
    assert checkPassword(hashed, password)  # Hashed password should match input password

def test_login_success_and_failure(client):
    hashed = hashPassword("Test@123")
    user = User(username="testuser", password=hashed, admin=False)
    with app.app_context():
        db.session.add(user)
        db.session.commit()

    # Successful login
    response = client.post('/', data=dict(username="testuser", password="Test@123"), follow_redirects=True)
    assert b"home" in response.data  # Should redirect to home

    # Failed login
    response = client.post('/', data=dict(username="testuser", password="WrongPass"), follow_redirects=True)
    assert b"Invalid credentials" in response.data

def test_logout_clears_session(client):
    with client.session_transaction() as sess:
        sess['userId'] = 1
        sess['admin'] = True
    response = client.get('/logout', follow_redirects=True)
    with client.session_transaction() as sess:
        assert 'userId' not in sess
        assert 'admin' not in sess


# A03: Injection - Ensure SQL injection is prevented
def test_sql_injection_login(client):
    malicious_input = "' OR '1'='1 --"
    response = client.post('/', data=dict(username=malicious_input, password="Test@123"), follow_redirects=True)

    # Ensure the login is rejected — the app should not be vulnerable
    assert b"Invalid credentials" in response.data 


# A05: Security Misconfiguration - Validate username length and format (prevents weak configurations)
def test_username_validation_rejects_short_names():
    with app.app_context():
        db.create_all()
        errors = validateUsername("abc")
        assert "Username must be between 5 and 15 characters long." in errors

def test_password_validation_missing_special_char():
    errors = validatePassword("Password123")
    assert "Password must contain at least one special character." in errors


# A07: Cross-Site Scripting (XSS) - Ensure XSS protection by sanitizing user input
def test_xss_protection(client):
    malicious_input = "<script>alert('XSS')</script>"
    response = client.post('/feedback', data=dict(message=malicious_input), follow_redirects=True)
    assert b"XSS" not in response.data  # Should sanitize the input and not allow the script to execute
