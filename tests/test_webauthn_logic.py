import pytest
import sys
import os
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from models import db, User

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

def test_webauthn_registration_trust_threshold_fail(client):
    # Create user with login_count = 0
    with app.app_context():
        user = User(email='new@edtech.com', password_hash='hash', login_count=0)
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    
    # Login the user session
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
    
    response = client.post('/webauthn/register/begin', data=json.dumps({
        'method': 'passkey'
    }), content_type='application/json')
    
    assert response.status_code == 403
    assert b'Complete 5 successful logins' in response.data

def test_webauthn_registration_trust_threshold_pass(client):
    # Create user with login_count = 5
    with app.app_context():
        user = User(email='trusted@edtech.com', password_hash='hash', login_count=5)
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)
        sess['_fresh'] = True
        
    response = client.post('/webauthn/register/begin', data=json.dumps({
        'method': 'passkey'
    }), content_type='application/json')
    
    # Status should be 200 (Challenge generated)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'challenge' in data
    assert 'rp' in data

def test_webauthn_login_begin_unrecognized_email(client):
    response = client.post('/webauthn/login/begin', data=json.dumps({
        'email': 'nonexistent@edtech.com',
        'method': 'passkey'
    }), content_type='application/json')
    
    assert response.status_code == 404
    assert b'No credential found' in response.data
