import os
from flask import Flask, redirect, url_for, flash, render_template
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

from models import db, User
import auth_routes
import admin_routes
import profile_routes
import webauthn_routes

load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'this_is_a_secure_secret_key_for_flask_edtech')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edtech.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
CSRFProtect(app)

# GLOBAL INTRUSION PREVENTION SYSTEM (IPS) HOOK
import utils
@app.before_request
def ips_intercept():
    return utils.global_ips_hook()

@app.errorhandler(403)
def forbidden(e):
    # Flask error handlers receive the HTTPException object
    return render_template('403.html', error=e.description), 403

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize modules
app.register_blueprint(auth_routes.auth_bp)
app.register_blueprint(admin_routes.admin_bp, url_prefix='/admin')
app.register_blueprint(profile_routes.profile_bp, url_prefix='/profile')
app.register_blueprint(webauthn_routes.webauthn_bp)

# Bind OAuth
auth_routes.oauth.init_app(app)

with app.app_context():
    db.create_all()
    # Pre-seed Edtech Mock Entities (Admin, Student, Teacher)
    from models import AllowedTeacherEmail, AllowedStudentId
    from utils import auth_utils

    try:
        for adm_email in ["25252@yenepoya.edu.in", "28467@yenepoya.edu.in"]:
            admin = User.query.filter_by(email=adm_email).first()
            if not admin:
                admin = User(email=adm_email, password_hash=auth_utils.hash_string("AdminPass123!"), role="admin", is_2fa_required=False, login_count=10)
                db.session.add(admin)

        teacher = User.query.filter_by(email="teacher@yenepoya.edu.in").first()
        if not teacher:
            if not AllowedTeacherEmail.query.filter_by(email="teacher@yenepoya.edu.in").first():
                db.session.add(AllowedTeacherEmail(email="teacher@yenepoya.edu.in"))
            teacher = User(email="teacher@yenepoya.edu.in", password_hash=auth_utils.hash_string("TestPass123!"), role="teacher", is_2fa_required=False, login_count=5)
            db.session.add(teacher)

        student = User.query.filter_by(email="student@yenepoya.edu.in").first()
        if not student:
            if not AllowedStudentId.query.filter_by(campus_id="STUDENT-101").first():
                db.session.add(AllowedStudentId(campus_id="STUDENT-101"))
            student = User(email="student@yenepoya.edu.in", password_hash=auth_utils.hash_string("TestPass123!"), role="student", is_2fa_required=False, login_count=5)
            db.session.add(student)

        db.session.commit()
    except Exception as e:
        print(f"Skipping seeding (likely schema sync): {e}")
        db.session.rollback()

@app.route('/')
def index():
    return redirect(url_for('auth.login'))

if __name__ == '__main__':
    app.run(debug=True)
