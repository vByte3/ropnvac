from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import hmac
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
from sqlalchemy import or_
from dotenv import load_dotenv
from pathlib import Path
import calendar as _calendar
from functools import wraps
import os
import re
from collections import defaultdict

MAX_DAYS_PER_YEAR = 90
NEAR_LIMIT_THRESHOLD = 80

# Load environment variables from .env file (explicit path next to this file)
env_path = Path(__file__).resolve().parent / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=str(env_path))
else:
    # fallback to default lookup
    load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('FLASK_SECRET')
if not app.secret_key:
    raise ValueError("FLASK_SECRET environment variable must be set")

# Log whether admin user is configured (do NOT log the password)
try:
    admin_present = bool(os.environ.get('ADMIN_USER'))
    app.logger.info(f"ADMIN_USER configured: {admin_present}")
except Exception:
    pass

# Session security configuration
# Make the `Secure` flag configurable via ENV so local HTTP development still receives the CSRF cookie.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('1', 'true', 'yes')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# CSRF Protection
csrf = CSRFProtect(app)

db = SQLAlchemy(app)


def validate_password(password):
    """Validate password strength: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit"""
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre majuscule"
    if not re.search(r'[a-z]', password):
        return False, "Le mot de passe doit contenir au moins une lettre minuscule"
    if not re.search(r'[0-9]', password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    return True, ""


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    rio = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    rank = db.Column(db.String(10), nullable=False)  # PA or GPX
    date_limit = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(30), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='active')  # active, suspended


class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, declined
    service = db.Column(db.String(100), nullable=True)
    start_time = db.Column(db.String(10), nullable=True)  # HH:MM format
    end_time = db.Column(db.String(10), nullable=True)  # HH:MM format
    admin_note = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(120), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)


class AdminNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(120), nullable=False)


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    audience = db.Column(db.String(20), nullable=False, default='all')  # all or user
    target_rio = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(120), nullable=False)
    send_email = db.Column(db.Boolean, nullable=False, default=False)
    delivered_count = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default='sent')


def contract_window(signed_date: date, ref_date: date = None):
    """Return (contract_start, contract_end) for the current contract year."""
    if not ref_date:
        ref_date = datetime.today().date()

    def safe_replace_year(d, yr):
        try:
            return d.replace(year=yr)
        except ValueError:
            last = _calendar.monthrange(yr, d.month)[1]
            return date(yr, d.month, last)

    try_anniv = safe_replace_year(signed_date, ref_date.year)
    if try_anniv > ref_date:
        contract_start = safe_replace_year(signed_date, ref_date.year - 1)
    else:
        contract_start = try_anniv
    next_anniv = safe_replace_year(signed_date, contract_start.year + 1)
    contract_end = next_anniv - timedelta(days=1)
    return contract_start, contract_end


def user_usage(user, ref_date: date = None):
    start, end = contract_window(user.date_limit, ref_date)
    used = Availability.query.filter(Availability.user_id == user.id, Availability.date >= start, Availability.date <= end).count()
    remaining = max(0, MAX_DAYS_PER_YEAR - used)
    return used, remaining


def init_db():
    db.create_all()
    # Ensure default status value exists for existing rows
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


@app.before_request
def ensure_db():
    init_db()


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    # Set a CSRF token cookie (readable by JS) for double-submit verification
    try:
        token = generate_csrf()
        response.set_cookie('csrf_token', token, secure=app.config.get('SESSION_COOKIE_SECURE', False), httponly=False, samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'))
    except Exception:
        pass
    return response


def current_user():
    rio = session.get('rio')
    if not rio:
        return None
    return User.query.filter_by(rio=rio).first()


@app.route('/')
def index():
    user = current_user()
    if user:
        return redirect(url_for('calendar'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        surname = request.form.get('surname', '').strip()
        rio = request.form.get('rio', '').strip()
        password = request.form.get('password', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()

        if not (name and surname and rio and password and rank and date_limit_str):
            flash('Tous les champs sont obligatoires')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        if rank not in ('PA', 'GPX'):
            flash('Le grade doit être PA ou GPX')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg)
            # Do not re-populate password for security reasons
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format de date invalide')
            return render_template('register.html', name=name, surname=surname, rio=rio, rank=rank, date_limit=date_limit_str)

        existing = User.query.filter_by(rio=rio).first()
        if existing:
            flash('RIO déjà enregistré — veuillez vous connecter')
            return redirect(url_for('login'))

        user = User(name=name, surname=surname, rio=rio, password=generate_password_hash(password), rank=rank, date_limit=date_limit)
        db.session.add(user)
        db.session.commit()
        session['rio'] = rio
        flash('Inscription et connexion réussies')
        return redirect(url_for('calendar'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        rio = request.form.get('rio', '').strip()
        password = request.form.get('password', '').strip()
        if not (rio and password):
            flash('Le RIO et le mot de passe sont obligatoires')
            return redirect(url_for('login'))
        user = User.query.filter_by(rio=rio).first()
        if not user or not check_password_hash(user.password, password):
            flash('RIO ou mot de passe incorrect')
            return redirect(url_for('login'))
        if user.status != 'active':
            flash('Compte suspendu. Contactez un administrateur.')
            return redirect(url_for('login'))
        session['rio'] = rio
        return redirect(url_for('calendar'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('rio', None)
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        surname = request.form.get('surname', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()

        if not (surname and rank and date_limit_str):
            flash('All fields are required')
            return redirect(url_for('profile'))

        if rank not in ('PA', 'GPX'):
            flash('Rank must be PA or GPX')
            return redirect(url_for('profile'))

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format')
            return redirect(url_for('profile'))

        # Update editable fields only
        user.surname = surname
        user.rank = rank
        user.date_limit = date_limit
        db.session.commit()
        flash('Profile updated')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        # Normalize inputs and env values to avoid whitespace issues
        user = request.form.get('user', '')
        pwd = request.form.get('password', '')
        ADMIN_USER_RAW = os.environ.get('ADMIN_USER')
        ADMIN_PASS_RAW = os.environ.get('ADMIN_PASS')

        if not ADMIN_USER_RAW or not ADMIN_PASS_RAW:
            flash('Admin credentials not configured')
            return redirect(url_for('admin_login'))

        ADMIN_USER = ADMIN_USER_RAW.strip()
        ADMIN_PASS = ADMIN_PASS_RAW

        user_in = user.strip()
        pwd_in = pwd

        # Use constant-time comparison for password
        user_match = (user_in == ADMIN_USER)
        pass_match = hmac.compare_digest(pwd_in or '', ADMIN_PASS or '')

        # No verbose diagnostics in production; keep comparisons silent

        if user_match and pass_match:
            session['is_admin'] = True
            session.permanent = True
            return redirect(url_for('admin_index'))

        flash('Identifiants admin incorrects')
        return redirect(url_for('admin_login'))
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_index():
    q = request.args.get('q', '').strip()
    rank_filter = request.args.get('rank', '').strip().upper()
    sort = request.args.get('sort', 'id').strip() or 'id'

    base_query = User.query
    if q:
        like = f"%{q}%"
        base_query = base_query.filter(or_(User.name.ilike(like), User.surname.ilike(like), User.rio.ilike(like)))
    if rank_filter in ('PA', 'GPX'):
        base_query = base_query.filter(User.rank == rank_filter)

    users = base_query.all()

    entries = []
    for u in users:
        used, remaining = user_usage(u)
        entries.append({'user': u, 'used': used, 'remaining': remaining})

    sort_key_map = {
        'name': lambda e: e['user'].name.lower(),
        'surname': lambda e: e['user'].surname.lower(),
        'rio': lambda e: e['user'].rio.lower(),
        'rank': lambda e: e['user'].rank,
        'used_desc': lambda e: (-e['used'], e['user'].id),
        'used_asc': lambda e: (e['used'], e['user'].id),
        'id': lambda e: e['user'].id,
    }
    key = sort_key_map.get(sort, sort_key_map['id'])
    entries = sorted(entries, key=key)

    all_users = User.query.all()
    total_users = len(all_users)

    # Count vacation days requested in the current month across all reservists
    today = datetime.today().date()
    month_start = date(today.year, today.month, 1)
    last_day = _calendar.monthrange(today.year, today.month)[1]
    month_end = date(today.year, today.month, last_day)
    total_month_days = Availability.query.filter(Availability.date >= month_start, Availability.date <= month_end).count()

    near_limit_users = []
    for au in all_users:
        used, _ = user_usage(au)
        if used >= NEAR_LIMIT_THRESHOLD:
            near_limit_users.append({'user': au, 'used': used})

    return render_template(
        'admin_dashboard.html',
        entries=entries,
        total_users=total_users,
        total_month_days=total_month_days,
        near_limit_count=len(near_limit_users),
        near_limit_users=near_limit_users,
        near_limit_threshold=NEAR_LIMIT_THRESHOLD,
        q=q,
        rank_filter=rank_filter,
        sort=sort,
    )


@app.route('/admin/calendar_all')
@admin_required
def admin_calendar_all():
    rank_filter = request.args.get('rank', '').strip().upper()
    month = request.args.get('month', '').strip()

    today = datetime.today().date()

    if month:
        try:
            y, m = map(int, month.split('-'))
            start = date(y, m, 1)
            last_day = _calendar.monthrange(y, m)[1]
            end = date(y, m, last_day)
        except Exception:
            start = today
            m_plus = today.month + 2
            y = today.year + (m_plus - 1) // 12
            m_final = ((m_plus - 1) % 12) + 1
            end = date(y, m_final, _calendar.monthrange(y, m_final)[1])
    else:
        start = date(today.year, today.month, 1)
        m_plus = today.month + 2
        y = today.year + (m_plus - 1) // 12
        m_final = ((m_plus - 1) % 12) + 1
        end = date(y, m_final, _calendar.monthrange(y, m_final)[1])

    status_filter = request.args.get('status', 'approved').strip() or 'approved'
    
    query = Availability.query.join(User).filter(Availability.date >= start, Availability.date <= end)
    if rank_filter in ('PA', 'GPX'):
        query = query.filter(User.rank == rank_filter)
    if status_filter in ('pending', 'approved', 'declined'):
        query = query.filter(Availability.status == status_filter)
    elif status_filter == 'all':
        pass  # no filter

    avail_rows = query.order_by(Availability.date).all()

    grouped = defaultdict(list)
    for row in avail_rows:
        u = User.query.get(row.user_id)
        grouped[row.date.isoformat()].append({
            'id': row.id,
            'name': u.name,
            'surname': u.surname,
            'rio': u.rio,
            'rank': u.rank,
            'status': row.status,
            'service': row.service,
            'start_time': row.start_time,
            'end_time': row.end_time,
        })

    # Prepare events list for JS rendering
    events = []
    for ds, users in grouped.items():
        events.append({'date': ds, 'users': users})

    return render_template(
        'admin_calendar_all.html',
        start=start.isoformat(),
        end=end.isoformat(),
        events=events,
        rank_filter=rank_filter,
        status_filter=status_filter,
        month=month,
    )


@app.route('/admin/availability/<int:avail_id>/review', methods=['POST'])
@admin_required
def admin_review_availability(avail_id):
    avail = Availability.query.get_or_404(avail_id)
    action = request.form.get('action', '').strip()
    
    if action == 'approve':
        service = request.form.get('service', '').strip()
        start_time = request.form.get('start_time', '').strip()
        end_time = request.form.get('end_time', '').strip()
        admin_note = request.form.get('admin_note', '').strip()
        
        if not service or not start_time or not end_time:
            flash('Service, heure début et heure fin requis pour approuver')
            return redirect(url_for('admin_calendar_all'))
        
        avail.status = 'approved'
        avail.service = service
        avail.start_time = start_time
        avail.end_time = end_time
        avail.admin_note = admin_note or None
        avail.reviewed_by = os.environ.get('ADMIN_USER', 'admin')
        avail.reviewed_at = datetime.utcnow()
        db.session.commit()
        flash('Demande approuvée')
    
    elif action == 'decline':
        admin_note = request.form.get('admin_note', '').strip()
        avail.status = 'declined'
        avail.admin_note = admin_note or None
        avail.reviewed_by = os.environ.get('ADMIN_USER', 'admin')
        avail.reviewed_at = datetime.utcnow()
        db.session.commit()
        flash('Demande refusée')
    
    return redirect(url_for('admin_calendar_all'))


@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        body = request.form.get('body', '').strip()
        audience = request.form.get('audience', 'all').strip() or 'all'
        target_rio = request.form.get('target_rio', '').strip()

        if not title or not body:
            flash('Titre et message requis')
            return redirect(url_for('admin_announcements'))

        ann = Announcement(
            title=title,
            body=body,
            audience=audience,
            target_rio=target_rio or None,
            created_by=os.environ.get('ADMIN_USER', 'admin'),
            send_email=False,
            delivered_count=0,
        )
        db.session.add(ann)
        db.session.commit()

        flash('Annonce publiée')
        return redirect(url_for('admin_announcements'))

    announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template('admin_announcements.html', announcements=announcements)


@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        surname = request.form.get('surname', '').strip()
        rio = request.form.get('rio', '').strip()
        password = request.form.get('password', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        status = request.form.get('status', 'active').strip().lower() or 'active'

        if not (name and surname and rio and password and rank and date_limit_str):
            flash('Tous les champs obligatoires (mot de passe requis)')
            return redirect(url_for('admin_create_user'))

        if rank not in ('PA', 'GPX'):
            flash('Le grade doit être PA ou GPX')
            return redirect(url_for('admin_create_user'))

        if status not in ('active', 'suspended'):
            status = 'active'

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg)
            return redirect(url_for('admin_create_user'))

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format de date invalide')
            return redirect(url_for('admin_create_user'))

        existing = User.query.filter_by(rio=rio).first()
        if existing:
            flash('RIO déjà enregistré')
            return redirect(url_for('admin_create_user'))

        user = User(
            name=name,
            surname=surname,
            rio=rio,
            password=generate_password_hash(password),
            rank=rank,
            date_limit=date_limit,
            email=email or None,
            phone=phone or None,
            status=status,
        )
        db.session.add(user)
        db.session.commit()
        flash('Utilisateur créé')
        return redirect(url_for('admin_index'))

    return render_template('admin_create_user.html')


@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # Admin may edit all fields
        name = request.form.get('name', '').strip()
        surname = request.form.get('surname', '').strip()
        rio = request.form.get('rio', '').strip()
        rank = request.form.get('rank', '').strip().upper()
        date_limit_str = request.form.get('date_limit', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        status = request.form.get('status', 'active').strip().lower() or 'active'
        new_password = request.form.get('new_password', '').strip()

        if not (name and surname and rio and rank and date_limit_str):
            flash('Tous les champs sont obligatoires (sauf mot de passe)')
            return redirect(url_for('admin_edit_user', user_id=user.id))

        if rank not in ('PA', 'GPX'):
            flash('Le grade doit être PA ou GPX')
            return redirect(url_for('admin_edit_user', user_id=user.id))

        if status not in ('active', 'suspended'):
            status = 'active'

        if new_password:
            is_valid, error_msg = validate_password(new_password)
            if not is_valid:
                flash(error_msg)
                return redirect(url_for('admin_edit_user', user_id=user.id))

        try:
            date_limit = datetime.strptime(date_limit_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Format de date invalide')
            return redirect(url_for('admin_edit_user', user_id=user.id))

        user.name = name
        user.surname = surname
        user.rio = rio
        user.rank = rank
        user.date_limit = date_limit
        user.email = email or None
        user.phone = phone or None
        user.status = status
        if new_password:
            user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Utilisateur mis à jour')
        return redirect(url_for('admin_index'))
    # GET
    avails = Availability.query.filter_by(user_id=user.id).order_by(Availability.date).all()
    notes = AdminNote.query.filter_by(user_id=user.id).order_by(AdminNote.created_at.desc()).all()
    return render_template('admin_user.html', user=user, avails=avails, notes=notes)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # delete availabilities then user
    Availability.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('Utilisateur supprimé')
    return redirect(url_for('admin_index'))


@app.route('/admin/user/<int:user_id>/note', methods=['POST'])
@admin_required
def admin_add_note(user_id):
    user = User.query.get_or_404(user_id)
    note_text = request.form.get('note', '').strip()
    admin_name = os.environ.get('ADMIN_USER', 'admin')
    if not note_text:
        flash('Note vide')
        return redirect(url_for('admin_edit_user', user_id=user.id))
    note = AdminNote(user_id=user.id, note=note_text, created_by=admin_name)
    db.session.add(note)
    db.session.commit()
    flash('Note ajoutée')
    return redirect(url_for('admin_edit_user', user_id=user.id))


@app.route('/calendar')
def calendar():
    user = current_user()
    if not user:
        return redirect(url_for('login'))

    # Use today's date as the visible/selectable start (user's contract date is still stored)
    today = datetime.today().date()
    start = today
    # end = last day of the month 3 months after the current month
    m = today.month + 3
    y = today.year + (m - 1) // 12
    m = ((m - 1) % 12) + 1
    end = date(y, m, _calendar.monthrange(y, m)[1])

    # compute contract year window based on user's signed date (date_limit)
    signed = user.date_limit
    def safe_replace_year(d, yr):
        try:
            return d.replace(year=yr)
        except ValueError:
            # handle Feb 29 -> use last day of Feb
            last = _calendar.monthrange(yr, d.month)[1]
            return date(yr, d.month, last)

    # find most recent anniversary <= today
    today = datetime.today().date()
    try_anniv = safe_replace_year(signed, today.year)
    if try_anniv > today:
        contract_start = safe_replace_year(signed, today.year - 1)
    else:
        contract_start = try_anniv
    next_anniv = safe_replace_year(signed, contract_start.year + 1)
    contract_end = next_anniv - timedelta(days=1)

    avails = Availability.query.filter_by(user_id=user.id).all()
    selected = [d.date.isoformat() for d in avails]

    # Build availability details map for calendar display
    avail_details = {}
    for a in avails:
        avail_details[a.date.isoformat()] = {
            'status': a.status,
            'service': a.service,
            'start_time': a.start_time,
            'end_time': a.end_time,
            'admin_note': a.admin_note,
        }

    # count how many days already used in this contract year
    used_count = Availability.query.filter(Availability.user_id == user.id, Availability.date >= contract_start, Availability.date <= contract_end).count()
    remaining = max(0, 90 - used_count)

    announcements = Announcement.query.filter(
        or_(Announcement.audience == 'all', Announcement.target_rio == user.rio)
    ).order_by(Announcement.created_at.desc()).limit(3).all()

    return render_template(
        'calendar.html',
        user=user,
        start=start.isoformat(),
        end=end.isoformat(),
        selected=selected,
        avail_details=avail_details,
        used_count=used_count,
        remaining=remaining,
        announcements=announcements,
    )


@app.route('/save_availabilities', methods=['POST'])
def save_availabilities():
    user = current_user()
    if not user:
        return jsonify({'ok': False, 'message': 'Not authenticated'}), 401

    data = request.get_json() or {}
    dates = data.get('dates', [])
    parsed = []
    try:
        for ds in dates:
            parsed.append(datetime.strptime(ds, '%Y-%m-%d').date())
    except Exception:
        return jsonify({'ok': False, 'message': 'Invalid date format in payload'}), 400

    # Validate against today's date window (today -> today+90)
    today = datetime.today().date()
    start = today
    m = today.month + 3
    y = today.year + (m - 1) // 12
    m = ((m - 1) % 12) + 1
    end = date(y, m, _calendar.monthrange(y, m)[1])
    for d in parsed:
        if not (start <= d <= end):
            return jsonify({'ok': False, 'message': f'Date {d.isoformat()} outside allowed range'}), 400

    # compute contract window
    signed = user.date_limit
    def safe_replace_year(d, yr):
        try:
            return d.replace(year=yr)
        except ValueError:
            last = _calendar.monthrange(yr, d.month)[1]
            return date(yr, d.month, last)

    today = datetime.today().date()
    try_anniv = safe_replace_year(signed, today.year)
    if try_anniv > today:
        contract_start = safe_replace_year(signed, today.year - 1)
    else:
        contract_start = try_anniv
    next_anniv = safe_replace_year(signed, contract_start.year + 1)
    contract_end = next_anniv - timedelta(days=1)

    # existing entries in visible window (we will replace only these)
    existing_visible = Availability.query.filter(Availability.user_id == user.id, Availability.date >= start, Availability.date <= end).all()
    existing_visible_set = set(a.date.isoformat() for a in existing_visible)

    # existing entries in contract window
    existing_contract = Availability.query.filter(Availability.user_id == user.id, Availability.date >= contract_start, Availability.date <= contract_end).all()
    existing_contract_set = set(a.date.isoformat() for a in existing_contract)

    parsed_set = set(d.isoformat() for d in parsed)
    parsed_in_contract = set(ds for ds in parsed_set if contract_start.isoformat() <= ds <= contract_end.isoformat())

    # final contract-year set equals existing_contract minus replaced visible entries, plus parsed_in_contract
    final_contract_set = (existing_contract_set - existing_visible_set) | parsed_in_contract
    if len(final_contract_set) > 90:
        return jsonify({'ok': False, 'message': f'Would exceed 90 work days in contract year (would be {len(final_contract_set)})'}), 400

    # delete only entries in the visible window that are NOT in parsed dates
    dates_to_delete = existing_visible_set - parsed_set
    for ds in dates_to_delete:
        Availability.query.filter(Availability.user_id == user.id, Availability.date == ds).delete(synchronize_session=False)
    
    # add new dates that don't already exist
    dates_to_add = parsed_set - existing_visible_set
    for ds in dates_to_add:
        d = datetime.strptime(ds, '%Y-%m-%d').date()
        a = Availability(user_id=user.id, date=d, status='pending')
        db.session.add(a)
    db.session.commit()
    return jsonify({'ok': True})


# Note: application entrypoint moved to the end so all routes are registered first.


# Debug endpoints and verbose diagnostics removed for release builds.


if __name__ == '__main__':
    app.run(debug=False)
