import os
import io
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from dotenv import load_dotenv
import pyotp
import qrcode

# Carga variables de entorno desde .env (NO incluir .env en el repo)
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'devkey-do-not-use-in-prod')

DB_USER = os.getenv('DATABASE_USER', 'root')
DB_PASS = os.getenv('DATABASE_PASSWORD', '')
DB_HOST = os.getenv('DATABASE_HOST', '127.0.0.1')
DB_NAME = os.getenv('DATABASE_NAME', 'mi_app')

# Cadena de conexión (usa PyMySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- Modelo User ----------
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    document_number = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    twofa_secret = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- util: generar QR B64 ----------
def qrcode_data_uri(provisioning_uri):
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/png;base64,{b64}"

# ---------- Rutas ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password')
        doc = request.form.get('document_number')
        phone = request.form.get('phone')

        if not full_name or not email or not password:
            flash('Rellena los campos obligatorios', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('El correo ya está registrado', 'danger')
            return redirect(url_for('register'))

        user = User(full_name=full_name, email=email, document_number=doc, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registro exitoso. Ahora inicia sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Credenciales incorrectas', 'danger')
            return redirect(url_for('login'))

        # Si tiene 2FA configurado: pedir TOTP
        if user.twofa_secret:
            session['pre_2fa_userid'] = user.id
            return redirect(url_for('two_factor'))
        # Si no tiene 2FA, iniciar sesión directamente
        login_user(user)
        flash('Has iniciado sesión', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/two_factor', methods=['GET','POST'])
def two_factor():
    user_id = session.get('pre_2fa_userid')
    if not user_id:
        flash('No hay sesión a verificar', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        if not token:
            flash('Introduce el código 2FA', 'danger')
            return redirect(url_for('two_factor'))
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(token, valid_window=1):
            login_user(user)
            session.pop('pre_2fa_userid', None)
            flash('2FA verificado. Bienvenido.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Código 2FA inválido', 'danger')
            return redirect(url_for('two_factor'))

    return render_template('two_factor.html')

@app.route('/enable_2fa', methods=['GET','POST'])
@login_required
def enable_2fa():
    # Si ya lo tiene
    if current_user.twofa_secret:
        flash('Ya tienes 2FA habilitado.', 'info')
        return redirect(url_for('dashboard'))

    # GET: generar secreto temporal y mostrar QR
    if request.method == 'GET':
        secret = pyotp.random_base32()
        session['twofa_secret_pending'] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='MiAppFlask')
        qr_uri = qrcode_data_uri(uri)
        return render_template('enable_2fa.html', qr_uri=qr_uri)

    # POST: verificar token y guardar secreto en DB
    token = request.form.get('token', '').strip()
    secret = session.get('twofa_secret_pending')
    if not secret:
        flash('Error: no hay secreto temporal. Intenta de nuevo.', 'danger')
        return redirect(url_for('enable_2fa'))

    totp = pyotp.TOTP(secret)
    if totp.verify(token, valid_window=1):
        # guardar en la base de datos (obteniendo la instancia real)
        user = User.query.get(current_user.id)
        user.twofa_secret = secret
        db.session.commit()
        session.pop('twofa_secret_pending', None)
        flash('2FA activado correctamente.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Código inválido. Revisa la hora del teléfono o vuelve a intentar.', 'danger')
        return redirect(url_for('enable_2fa'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/users')
@login_required
def users_list():
    # Solo admin puede ver lista (ejemplo)
    if current_user.role != 'admin':
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('index'))

# ---------- inicio ----------
if __name__ == '__main__':
    # Crea tablas si no existen (solo desarrollo)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
