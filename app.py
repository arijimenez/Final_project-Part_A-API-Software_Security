from flask import Flask, render_template, jsonify, make_response, request, redirect, url_for, abort
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

import os
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#app.config['JWT_SECRET_KEY'] = '!D18@23J15-'  #  Primera vulnerabilidad encontrado con bandit consistia en la seguridad de la contaseña
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_value') #Correccion de la primera vulnerabilidad
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 600 #Duracion del token antes de expirar
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
app.config['JWT_QUERY_STRING_NAME'] = 'token'
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Recarga automática de plantillas

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

limiter = Limiter(app=app, key_func=get_remote_address,storage_uri="redis://localhost:6379/0")
limiter.init_app(app)

#--------------------------------------CLASSES-------------------------------------------------
#User Class---------------------------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(10), nullable=True)
    @classmethod
    def create_user(cls, username, password, role=role):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = cls(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return new_user
    
#Audit CLass-------------------------------------------------------------------------------------
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(15), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    level = db.Column(db.String(10), nullable=False)
    
    def __init__(self, user_id, username, method, level):
        self.user_id = user_id
        self.username = username
        self.method = method
        self.timestamp = datetime.datetime.utcnow()
        self.level = level
# Role Class --------------------------------------------------------------------------------
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    permissions = db.Column(db.String(200), nullable=False)
#------------------------------------------------FUNCTIONS------------------------------------------
def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            current_user = get_jwt_identity()
            claims = get_jwt()

            if 'role' not in claims:
                abort(403, 'Role not found in token claims')

            user_role = claims['role']

            if user_role not in roles:
                abort(403, 'Insufficient permissions')

            return fn(*args, **kwargs)

        return decorator

    return wrapper
# Get Audit---------------------------------------------------------------------------------------
@app.route('/audit_log', methods=['GET'])
def audit_log():
    audit_logs = AuditLog.query.all()
    audit_log_list = [{
        'id': log.id,
        'user_id': log.user_id,
        'username': log.username,
        'method': log.method,
        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'level': log.level,
    } for log in audit_logs]
    return jsonify({'audit_logs': audit_log_list})
# Get Users -------------------------------------------------------------------------------------------------------- Borrar
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'username': user.username, 'role': user.role, 'password': user.password} for user in users]
    return jsonify({'users': user_list})


# Register user----------------------------------------------------------------------------------------
@app.route('/register', methods=['POST'])
@limiter.limit("2 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if User.query.filter_by(username=username).first():
        # Registra el evento de auditoría (ERROR)
        log_event(username, 'register', 'ERROR')
        return jsonify({'error': 'Username already exists'}), 400

    User.create_user(username=username, password=password, role=role)
    # Registra el evento de auditoría (INFO)
    log_event(username, 'register', 'INFO')
    return jsonify({'message': 'User created successfully'}), 201
    
#Login user----------------------------------------------------------------------------------------------------------
@app.route('/login', methods=['GET'])
@limiter.limit("3 per minute")
def login():
    return '''
        <form action="/login" method="post">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
    '''
@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute")
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Asegúrate de incluir el claim 'role' al crear el token
        access_token = create_access_token(identity=username, additional_claims={'role': user.role})
        print(f"Token generado: {access_token}")

        # Registra el evento de auditoría (INFO)
        log_event(username, 'login', 'INFO')
        return redirect(url_for('index', token=access_token))
    else:
        # Registra el evento de auditoría (ERROR)
        log_event(username, 'login', 'ERROR')
        return redirect(url_for('login'))

#Log Event----------------------------------------------------------------------------------------------------------------
def log_event(username, method, default_level='INFO'):
    user = User.query.filter_by(username=username).first()

    # Establece el nivel de registro predeterminado
    level = default_level

    # Verifica el rol del usuario y ajusta el nivel si es necesario
    if user:
        if user.role == 'ADMIN':
            level = 'INFO'
        elif user.role == 'USER':
            level = 'WARNING'

        audit_log = AuditLog(user_id=user.id, username=username, method=method, level=level)
        db.session.add(audit_log)
        db.session.commit()
# -------------------------------------------------IMPLEMENT SECURE APP--------------------------------------
# Index HTML protected---------------------------------------------------------------------------------------
@app.route('/', methods=['GET'])
@limiter.limit("5 per minute")  # Flask limiter
@jwt_required() 
@roles_required('ADMIN', 'USER')
def index():
    template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Signals v2.3')
    app.template_folder = template_folder

    try:
        current_user = get_jwt_identity()

        # Asegúrate de que el usuario tenga un rol asignado en su token
        claims = get_jwt()
        if 'role' not in claims:
            raise ValueError('Role not found in token claims')

        user_role = claims['role']
        print(f"Usuario {current_user} tiene el rol: {user_role}")

        # Registra el evento de auditoría (INFO)
        log_event(current_user, 'access_protected_route', 'INFO')

        # Renderiza la plantilla según el rol del usuario
        return render_template('index.html', current_user=current_user, user_role=user_role)
    except RateLimitExceeded as e:
        # Registra el evento de auditoría (ERROR)
        log_event(current_user, 'access_protected_route', 'ERROR')
        response = {
            'error': 'ratelimit exceeded',
            'description': e.description,
            'retry_after': e.retry_after,
        }
        return make_response(jsonify(response), 429)
    except Exception as e:
        # Registra el evento de auditoría (ERROR)
        log_event(current_user, 'access_protected_route', 'ERROR')
        response = {
            'error': 'Invalid or missing token',
            'description': str(e),
        }
        return make_response(jsonify(response), 401)


#-------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    #Esta vulnerabilidad consiste en tener la depuracion en tiempo real activada
    #app.run(debug=True, host='localhost', port=5000) # Segunda vulnerabilidad encontrada por bandit
    app.run(debug=False, host='localhost', port=5000, ssl_context=('cert.pem', 'key.pem')) #Correccion de la segunda vulnerabilidad

