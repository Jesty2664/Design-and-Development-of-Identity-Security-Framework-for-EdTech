from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from models import db, User, AllowedStudentId, AllowedTeacherEmail, IPBlacklist, AuditLog
from datetime import datetime, timedelta
from utils import lattice_crypto
import functools

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    users = User.query.all()
    blacklists = IPBlacklist.query.filter(IPBlacklist.blocked_until > datetime.utcnow()).all()
    students = AllowedStudentId.query.all()
    teachers = AllowedTeacherEmail.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()
    
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    recent_logs = [l for l in logs if l.timestamp >= twenty_four_hours_ago]
    threat_count = sum(1 for l in recent_logs if l.action == "SECURITY_INCIDENT")

    # Fetch Clearance Requests
    from models import ClearanceRequest
    clearance_reqs = ClearanceRequest.query.filter_by(status='pending').order_by(ClearanceRequest.created_at.desc()).all()

    return render_template(
        'admin_dashboard.html', 
        users=users, 
        students=students, 
        teachers=teachers, 
        logs=logs,
        threat_count=threat_count,
        clearance_requests=clearance_reqs
    )

@admin_bp.route('/whitelist/student', methods=['POST'])
@login_required
@admin_required
def add_student():
    campus_id = request.form.get('campus_id')
    if AllowedStudentId.query.filter_by(campus_id=campus_id).first():
        flash('Campus ID already exists.', 'warning')
    else:
        db.session.add(AllowedStudentId(campus_id=campus_id))
        db.session.commit()
        
        # PQC Audit Trail
        log_entry = f"WHITELIST_ADD_STUDENT: {campus_id}"
        pqc_sig = lattice_crypto.sign_audit_entry(log_entry, lattice_crypto.generate_keypair()['private'])
        db.session.add(AuditLog(action="WHITELIST_ADD", user_id=current_user.id, details=log_entry, pqc_signature=pqc_sig))
        db.session.commit()
        
        flash('Added Campus ID.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/whitelist/student/upload', methods=['POST'])
@login_required
@admin_required
def upload_students():
    file = request.files.get('file')
    if not file or not file.filename.endswith('.txt'):
        flash('Please upload a valid .txt file.', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    content = file.read().decode('utf-8')
    lines = content.splitlines()
    added_count = 0
    for line in lines:
        cid = line.strip()
        if cid and not AllowedStudentId.query.filter_by(campus_id=cid).first():
            db.session.add(AllowedStudentId(campus_id=cid))
            added_count += 1
    
    db.session.commit()
    flash(f'Successfully added {added_count} Student IDs from file.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/whitelist/teacher', methods=['POST'])
@login_required
@admin_required
def add_teacher():
    email = request.form.get('email')
    if AllowedTeacherEmail.query.filter_by(email=email).first():
        flash('Teacher email already exists.', 'warning')
    else:
        db.session.add(AllowedTeacherEmail(email=email))
        db.session.commit()
        flash('Added Teacher Email.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/whitelist/teacher/upload', methods=['POST'])
@login_required
@admin_required
def upload_teachers():
    file = request.files.get('file')
    if not file or not file.filename.endswith('.txt'):
        flash('Please upload a valid .txt file.', 'danger')
        return redirect(url_for('admin.dashboard'))
    
    content = file.read().decode('utf-8')
    lines = content.splitlines()
    added_count = 0
    for line in lines:
        email = line.strip()
        if email and not AllowedTeacherEmail.query.filter_by(email=email).first():
            db.session.add(AllowedTeacherEmail(email=email))
            added_count += 1
            
    db.session.commit()
    flash(f'Successfully added {added_count} Teacher emails from file.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/whitelist/delete_student/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_student(id):
    student = AllowedStudentId.query.get(id)
    if student:
        db.session.delete(student)
        db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/whitelist/delete_teacher/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_teacher(id):
    teacher = AllowedTeacherEmail.query.get(id)
    if teacher:
        db.session.delete(teacher)
        db.session.commit()
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/unblock/<int:id>', methods=['POST'])
@login_required
@admin_required
def unblock_ip(id):
    ip = IPBlacklist.query.get(id)
    if ip:
        db.session.delete(ip)
        db.session.commit()
        flash(f'IP {ip.ip_address} unblocked manually.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/user/reset_2fa/<int:id>', methods=['POST'])
@login_required
@admin_required
def reset_2fa(id):
    user = User.query.get(id)
    if user:
        user.is_2fa_required = True
        user.totp_secret = None
        for bc in user.backup_codes:
            db.session.delete(bc)
        db.session.commit()
        
        # PQC Audit Trail
        log_entry = f"RESET_2FA: {user.email}"
        pqc_sig = lattice_crypto.sign_audit_entry(log_entry, lattice_crypto.generate_keypair()['private'])
        db.session.add(AuditLog(action="USER_SECURITY_RESET", user_id=current_user.id, details=log_entry, pqc_signature=pqc_sig))
        db.session.commit()
        
        flash(f'2FA Reset for {user.email}. They will be prompted to re-enroll.', 'info')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/clearance/approve/<int:id>', methods=['POST'])
@login_required
@admin_required
def approve_clearance(id):
    from models import ClearanceRequest, AllowedStudentId, AllowedTeacherEmail, IPBlacklist, AuditLog, db
    req = ClearanceRequest.query.get_or_404(id)
    
    if req.status != 'pending':
        flash('Request already processed.', 'warning')
        return redirect(url_for('admin.dashboard'))
        
    req.status = 'approved'
    log_detail = f"Approved clearance for {req.identifier}"
    
    if req.request_type == 'identity':
        if req.role_requested == 'student':
            if not AllowedStudentId.query.filter_by(campus_id=req.identifier).first():
                db.session.add(AllowedStudentId(campus_id=req.identifier))
        elif req.role_requested == 'teacher':
            if not AllowedTeacherEmail.query.filter_by(email=req.identifier).first():
                db.session.add(AllowedTeacherEmail(email=req.identifier))
    elif req.request_type == 'ip':
        ip_rec = IPBlacklist.query.filter_by(ip_address=req.identifier).first()
        if ip_rec:
            # Drop them from blacklist
            db.session.delete(ip_rec)
            
    db.session.add(AuditLog(action="CLEARANCE_APPROVED", details=log_detail))
    db.session.commit()
    
    flash(f"Approved {req.request_type} clearance for {req.identifier}", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/clearance/decline/<int:id>', methods=['POST'])
@login_required
@admin_required
def decline_clearance(id):
    from models import ClearanceRequest, AuditLog, db
    req = ClearanceRequest.query.get_or_404(id)
    
    if req.status != 'pending':
        flash('Request already processed.', 'warning')
        return redirect(url_for('admin.dashboard'))
        
    req.status = 'declined'
    db.session.add(AuditLog(action="CLEARANCE_DECLINED", details=f"Declined clearance for {req.identifier}"))
    db.session.commit()
    
    flash(f"Declined clearance for {req.identifier}", "info")
    return redirect(url_for('admin.dashboard'))
