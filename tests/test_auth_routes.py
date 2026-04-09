import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from models import db, User, AllowedStudentId, AllowedTeacherEmail

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
        with app.app_context():
            db.drop_all()

def test_registration_student_success(client):
    # Setup whitelist
    with app.app_context():
        db.session.add(AllowedStudentId(campus_id="STUDENT-123"))
        db.session.commit()
    
    response = client.post('/register', data={
        'email': 'student@edtech.com',
        'password': 'Password123!',
        'role': 'student',
        'identifier': 'STUDENT-123'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'configure Two-Factor Authentication' in response.data
    
    with app.app_context():
        user = User.query.filter_by(email='student@edtech.com').first()
        assert user is not None
        assert user.role == "student"

def test_registration_student_fail_identifer(client):
    response = client.post('/register', data={
        'email': 'student@edtech.com',
        'password': 'Password123!',
        'role': 'student',
        'identifier': 'WRONG-ID'
    }, follow_redirects=True)
    
    assert b'Invalid Campus ID. Registration denied.' in response.data
    
    with app.app_context():
        user = User.query.filter_by(email='student@edtech.com').first()
        assert user is None

def test_login_flow_phase_1(client):
    # Create user
    from utils.auth_utils import hash_string
    with app.app_context():
        # Ensure user has 2FA disabled for Phase 1 direct login
        user = User(email='login@edtech.com', password_hash=hash_string('Pass123!'), role='student', is_2fa_required=False)
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/login', data={
        'email': 'login@edtech.com',
        'password': 'Pass123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    # Check for strings present in base.html or dashboard.html
    assert b'Portal' in response.data or b'Welcome' in response.data or b'Aether' in response.data

def test_login_flow_redirect_to_2fa(client):
    from utils.auth_utils import hash_string
    with app.app_context():
        user = User(email='2fa@edtech.com', password_hash=hash_string('Pass123!'), role='student', is_2fa_required=True)
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/login', data={
        'email': '2fa@edtech.com',
        'password': 'Pass123!'
    }, follow_redirects=False)
    
    assert response.status_code == 302
    assert '/verify-2fa' in response.location
