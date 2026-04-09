import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from models import db, User, BackupCode, AllowedStudentId, AllowedTeacherEmail

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

def test_user_creation(client):
    user = User(email="test@edtech.com", password_hash="hashed", role="student")
    db.session.add(user)
    db.session.commit()
    
    saved_user = User.query.filter_by(email="test@edtech.com").first()
    assert saved_user is not None
    assert saved_user.role == "student"

def test_user_relationship_backup_codes(client):
    user = User(email="backup@edtech.com", password_hash="hashed")
    db.session.add(user)
    db.session.commit()
    
    code = BackupCode(user_id=user.id, code_hash="codehash")
    db.session.add(code)
    db.session.commit()
    
    assert len(user.backup_codes) == 1
    assert user.backup_codes[0].code_hash == "codehash"

def test_unique_email_constraint(client):
    user1 = User(email="unique@edtech.com", password_hash="hashed")
    db.session.add(user1)
    db.session.commit()
    
    user2 = User(email="unique@edtech.com", password_hash="hashed")
    db.session.add(user2)
    
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        db.session.commit()

def test_whitelisting_models(client):
    student_id = AllowedStudentId(campus_id="STUDENT-X")
    teacher_email = AllowedTeacherEmail(email="vetted@teacher.com")
    
    db.session.add(student_id)
    db.session.add(teacher_email)
    db.session.commit()
    
    assert AllowedStudentId.query.filter_by(campus_id="STUDENT-X").first() is not None
    assert AllowedTeacherEmail.query.filter_by(email="vetted@teacher.com").first() is not None
