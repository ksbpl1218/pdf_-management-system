import os
import logging
from datetime import datetime, timedelta
from functools import wraps
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from sqlalchemy import text

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///pdf_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_S3_BUCKET_NAME = os.environ.get('AWS_S3_BUCKET_NAME')
AWS_S3_REGION = os.environ.get('AWS_S3_REGION', 'us-east-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')

# Initialize extensions
db = SQLAlchemy(app)

# Initialize S3 client
try:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_S3_REGION
    )
    logger.info("S3 client initialized successfully")
except Exception as e:
    logger.error(f"Error initializing S3 client: {e}")
    s3_client = None

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='view_only')  # 'view_only' or 'admin'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'isActive': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(500), nullable=True)
    permission_level = db.Column(db.String(50), nullable=False, default='view_only')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='folder', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'path': self.path,
            'permissionLevel': self.permission_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'file_count': len(self.files)
        }

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.original_filename,
            'filename': self.filename,
            'size': self.file_size,
            'folderId': self.folder_id,
            'folderName': self.folder.name if self.folder else None,
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None
        }

class UserPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    permission_level = db.Column(db.String(50), nullable=False, default='view_only')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'folder_id'),)

# Utility Functions
def generate_random_password(length=12):
    """Generate a random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

def send_email(to_email, subject, body):
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USERNAME
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_USERNAME, to_email, text)
        server.quit()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False

def upload_file_to_s3(file, filename):
    """Upload file to S3 and return the key"""
    try:
        s3_key = f"uploads/{filename}"
        s3_client.upload_fileobj(
            file,
            AWS_S3_BUCKET_NAME,
            s3_key,
            ExtraArgs={'ContentType': 'application/pdf'}
        )
        return s3_key
    except Exception as e:
        logger.error(f"Error uploading file to S3: {e}")
        return None

def delete_file_from_s3(s3_key):
    """Delete file from S3"""
    try:
        s3_client.delete_object(Bucket=AWS_S3_BUCKET_NAME, Key=s3_key)
        return True
    except Exception as e:
        logger.error(f"Error deleting file from S3: {e}")
        return False

def get_file_from_s3(s3_key):
    """Get file from S3"""
    try:
        response = s3_client.get_object(Bucket=AWS_S3_BUCKET_NAME, Key=s3_key)
        return response['Body']
    except Exception as e:
        logger.error(f"Error getting file from S3: {e}")
        return None

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user or not current_user.is_active:
                return jsonify({'message': 'Invalid token'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Database initialization
@app.before_request
def create_tables():
    if not hasattr(app, 'tables_created'):
        try:
            logger.info("Starting database initialization...")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Check if admin user exists
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin',
                    is_active=True
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Default admin user created")
            else:
                logger.info("Admin user already exists")
            
            app.tables_created = True
            logger.info("Database initialization completed successfully")
        except Exception as e:
            logger.error(f"Error during database initialization: {e}")
            db.session.rollback()

# Routes
@app.route('/')
def index():
    return send_from_directory('.', 'admin_dashboard.html')

@app.route('/login.html')
def login_page():
    return send_from_directory('.', 'login.html')

@app.route('/admin_dashboard.html')
def admin_dashboard():
    return send_from_directory('.', 'admin_dashboard.html')

# Authentication API Routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
        
        # Check by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        if not user.is_active:
            return jsonify({'message': 'Account is deactivated'}), 401
        
        # Generate JWT token
        token = jwt.encode(
            {
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        return jsonify({
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/auth/verify', methods=['GET'])
def verify_token():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        if token.startswith('Bearer '):
            token = token[7:]
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        if not user or not user.is_active:
            return jsonify({'message': 'Invalid token'}), 401
        return jsonify({'valid': True, 'user': user.to_dict()}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'message': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'Email not found'}), 404
        
        # Generate new password
        new_password = generate_random_password()
        user.set_password(new_password)
        db.session.commit()
        
        # Send email
        subject = "Password Reset - PDF Management System"
        body = f"""
        Hello {user.username},
        
        Your password has been reset. Your new login credentials are:
        
        Username: {user.username}
        Email: {user.email}
        New Password: {new_password}
        
        Please log in with these credentials and consider changing your password.
        
        Best regards,
        PDF Management System
        """
        
        if send_email(email, subject, body):
            return jsonify({'message': 'New password sent to your email'}), 200
        else:
            return jsonify({'message': 'Error sending email'}), 500
            
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({'message': 'Internal server error'}), 500

# User Management API Routes
@app.route('/api/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    try:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users]), 200
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/users', methods=['POST'])
@token_required
@admin_required
def create_user(current_user):
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field} is required'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already exists'}), 400
        
        user = User(
            username=data['username'],
            email=data['email'],
            role=data['role'],
            is_active=data.get('isActive', True)
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify(user.to_dict()), 201
        
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user(current_user, user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        user.is_active = data.get('isActive', user.is_active)
        
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        db.session.commit()
        return jsonify(user.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(current_user, user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent deleting the last admin user
        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin', is_active=True).count()
            if admin_count <= 1:
                return jsonify({'message': 'Cannot delete the last admin user'}), 400
        
        # Delete user permissions
        UserPermission.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>/permissions', methods=['POST'])
@token_required
@admin_required
def set_user_permissions(current_user, user_id):
    try:
        data = request.get_json()
        folder_ids = data.get('folderIds', [])
        permission_level = data.get('permissionLevel', 'view_only')
        
        # Delete existing permissions
        UserPermission.query.filter_by(user_id=user_id).delete()
        
        # Add new permissions
        for folder_id in folder_ids:
            permission = UserPermission(
                user_id=user_id,
                folder_id=folder_id,
                permission_level=permission_level
            )
            db.session.add(permission)
        
        db.session.commit()
        return jsonify({'message': 'Permissions updated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error setting user permissions: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

# Folder Management API Routes
@app.route('/api/folders', methods=['GET'])
@token_required
def get_folders(current_user):
    try:
        folders = Folder.query.all()
        return jsonify([folder.to_dict() for folder in folders]), 200
    except Exception as e:
        logger.error(f"Error getting folders: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/folders', methods=['POST'])
@token_required
@admin_required
def create_folder(current_user):
    try:
        data = request.get_json()
        
        if not data.get('name'):
            return jsonify({'message': 'Folder name is required'}), 400
        
        folder = Folder(
            name=data['name'],
            path=data.get('path', '/'),
            permission_level=data.get('permissionLevel', 'view_only')
        )
        
        db.session.add(folder)
        db.session.commit()
        
        return jsonify(folder.to_dict()), 201
        
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@token_required
@admin_required
def update_folder(current_user, folder_id):
    try:
        folder = Folder.query.get_or_404(folder_id)
        data = request.get_json()
        
        folder.name = data.get('name', folder.name)
        folder.path = data.get('path', folder.path)
        folder.permission_level = data.get('permissionLevel', folder.permission_level)
        
        db.session.commit()
        return jsonify(folder.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error updating folder: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_folder(current_user, folder_id):
    try:
        folder = Folder.query.get_or_404(folder_id)
        
        # Delete all files in the folder from S3
        for file in folder.files:
            delete_file_from_s3(file.s3_key)
        
        # Delete folder permissions
        UserPermission.query.filter_by(folder_id=folder_id).delete()
        
        # Delete the folder (this will cascade delete files due to relationship)
        db.session.delete(folder)
        db.session.commit()
        
        return jsonify({'message': 'Folder deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error deleting folder: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/folders/<int:folder_id>/rename', methods=['PUT'])
@token_required
@admin_required
def rename_folder(current_user, folder_id):
    try:
        folder = Folder.query.get_or_404(folder_id)
        data = request.get_json()
        
        new_name = data.get('name', '').strip()
        if not new_name:
            return jsonify({'message': 'Folder name is required'}), 400
        
        folder.name = new_name
        db.session.commit()
        
        return jsonify(folder.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error renaming folder: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

# File Management API Routes
@app.route('/api/files', methods=['GET'])
@token_required
def get_files(current_user):
    try:
        files = File.query.all()
        return jsonify([file.to_dict() for file in files]), 200
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/files/upload', methods=['POST'])
@token_required
@admin_required
def upload_files(current_user):
    try:
        folder_id = request.form.get('folderId')
        if not folder_id:
            return jsonify({'message': 'Folder ID is required'}), 400
        
        folder = Folder.query.get_or_404(folder_id)
        
        if 'files' not in request.files:
            return jsonify({'message': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        uploaded_files = []
        
        for file in files:
            if file.filename == '':
                continue
                
            if not file.filename.lower().endswith('.pdf'):
                continue
            
            # Generate secure filename
            original_filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{original_filename}"
            
            # Upload to S3
            s3_key = upload_file_to_s3(file, filename)
            if not s3_key:
                continue
            
            # Save to database
            file_record = File(
                filename=filename,
                original_filename=original_filename,
                file_size=len(file.read()),
                s3_key=s3_key,
                folder_id=folder_id
            )
            
            # Reset file pointer after reading size
            file.seek(0)
            
            db.session.add(file_record)
            uploaded_files.append(file_record)
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully uploaded {len(uploaded_files)} files',
            'files': [f.to_dict() for f in uploaded_files]
        }), 200
        
    except Exception as e:
        logger.error(f"Error uploading files: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_file(current_user, file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        # Delete from S3
        delete_file_from_s3(file.s3_key)
        
        # Delete from database
        db.session.delete(file)
        db.session.commit()
        
        return jsonify({'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        db.session.rollback()
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/api/files/<int:file_id>/view', methods=['GET'])
@token_required
def view_file(current_user, file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        # Get file from S3
        file_obj = get_file_from_s3(file.s3_key)
        if not file_obj:
            return jsonify({'message': 'File not found'}), 404
        
        return send_file(
            file_obj,
            as_attachment=False,
            download_name=file.original_filename,
            mimetype='application/pdf'
        )
        
    except Exception as e:
        logger.error(f"Error viewing file: {e}")
        return jsonify({'message': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = '0.0.0.0'  # This is crucial for Render deployment
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info(f"Starting Flask app on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
