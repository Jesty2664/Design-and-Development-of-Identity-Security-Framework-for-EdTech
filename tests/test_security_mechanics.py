import pytest
import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from models import db, User, IPBlacklist, AllowedStudentId
from utils.auth_utils import hash_string

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
        with app.app_context():
            db.drop_all()

def test_account_lockout_after_failures(client):
    with app.app_context():
        user = User(email='bruteforce@edtech.com', password_hash=hash_string('Pass123!'))
        db.session.add(user)
        db.session.commit()
    
    # Fail 5 times
    for _ in range(5):
        client.post('/login', data={'email': 'bruteforce@edtech.com', 'password': 'WrongPassword'})
    
    with app.app_context():
        user = User.query.filter_by(email='bruteforce@edtech.com').first()
        assert user.failed_attempts == 5
        assert user.locked_until is not None
        assert user.locked_until > datetime.utcnow()

    # Try logging in while locked
    response = client.post('/login', data={'email': 'bruteforce@edtech.com', 'password': 'Pass123!'}, follow_redirects=True)
    assert b'Account locked' in response.data

def test_ip_blacklisting_on_registration_spam(client):
    # Try registering with invalid identifier 5 times
    # Note: Use a specific IP if needed, but the app uses request.remote_addr which defaults to 127.0.0.1 in tests
    for _ in range(5):
        client.post('/register', data={
            'email': 'spam@edtech.com',
            'password': 'Pass',
            'role': 'student',
            'identifier': 'FAKE-ID'
        })
    
    with app.app_context():
        record = IPBlacklist.query.filter_by(ip_address='127.0.0.1').first()
        assert record is not None
        assert record.failed_attempts >= 5
        assert record.blocked_until is not None

    # Next attempt should show blocked message
    response = client.post('/register', data={'email': 'other@edtech.com'}, follow_redirects=True)
    assert b'IP is temporarily blocked' in response.data

def test_rbac_student_denied_admin(client):
    with app.app_context():
        user = User(email='student@edtech.com', password_hash=hash_string('Pass'), role='student')
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
    
    # Try accessing admin dashboard
    response = client.get('/admin/dashboard', follow_redirects=True)
    
    # The admin_required decorator uses abort(403)
    assert response.status_code == 403
