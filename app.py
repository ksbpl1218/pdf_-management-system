from flask import Flask, request, jsonify, render_template, send_file, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import boto3
from datetime import datetime, timedelta
import json
from dotenv import load_dotenv
import io
from botocore.exceptions import ClientError
from functools import wraps
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')

# Database configuration - handle both local and production
database_url = os.getenv('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    # Fix for Heroku/Render postgres URL format
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration for password reset
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SENDER_EMAIL = os.getenv('SENDER_EMAIL', SMTP_USERNAME)

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
S3_BUCKET = os.getenv('S3_BUCKET')
S3_REGION = os.getenv('S3_REGION', 'us-east-1')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize S3 client only if credentials are provided
s3_client = None
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY and S3_BUCKET:
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=S3_REGION
        )
        logger.info("S3 client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {e}")
else:
    logger.warning("S3 credentials not provided - file uploads will be disabled")

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class Folder(db.Model):
    __tablename__ = 'folders'
    id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(255), nullable=False)
    folder_path = db.Column(db.String(500), nullable=False)
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)

    def __repr__(self):
        return f'<Folder {self.folder_name}>'

class PDFFile(db.Model):
    __tablename__ = 'pdf_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=False)
    file_size = db.Column(db.BigInteger, default=0)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<PDFFile {self.original_name}>'

class FolderPermission(db.Model):
    __tablename__ = 'folder_permissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=False)
    permission_level = db.Column(db.String(20), default='view')  # 'view' or 'admin'
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<FolderPermission user_id={self.user_id} folder_id={self.folder_id}>'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

# Helper Functions
def generate_random_password(length=10):
    """Generate a random password"""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def send_email(to_email, subject, body):
    """Send email using SMTP"""
    try:
        if not all([SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD]):
            logger.error("Email credentials not configured")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

# Decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def user_has_folder_permission(user_id, folder_id, required_level='view'):
    try:
        # Admins have access to everything
        user = User.query.get(user_id)
        if user and user.is_admin:
            return True
            
        permission = FolderPermission.query.filter_by(
            user_id=user_id, 
            folder_id=folder_id
        ).first()
        
        if not permission:
            return False
        
        # Permission mapping
        level_hierarchy = {'read': 1, 'view': 1, 'write': 2, 'admin': 3}
        user_level = level_hierarchy.get(permission.permission_level, 0)
        required_level_num = level_hierarchy.get(required_level, 1)
        
        return user_level >= required_level_num
    except Exception as e:
        logger.error(f"Error checking folder permission: {e}")
        return False

def upload_to_s3(file_obj, s3_key):
    if not s3_client:
        logger.error("S3 client not initialized")
        return False
    
    try:
        s3_client.upload_fileobj(
            file_obj,
            S3_BUCKET,
            s3_key,
            ExtraArgs={'ContentType': 'application/pdf'}
        )
        return True
    except Exception as e:
        logger.error(f"S3 upload error: {e}")
        return False

def get_pdf_from_s3(s3_key):
    """Fetch PDF content from S3 and return as bytes"""
    if not s3_client:
        logger.error("S3 client not initialized")
        return None
    
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return response['Body'].read()
    except ClientError as e:
        logger.error(f"S3 download error: {e}")
        return None

# Initialize database BEFORE routes
def init_db():
    """Initialize the database and create default admin user"""
    try:
        logger.info("Starting database initialization...")
        
        # Create all tables
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Check if admin user exists
        existing_admin = User.query.filter_by(username='admin').first()
        if existing_admin:
            logger.info("Admin user already exists")
            # Verify password hash is correct
            if not check_password_hash(existing_admin.password_hash, 'admin123'):
                logger.info("Updating admin password hash...")
                existing_admin.password_hash = generate_password_hash('admin123')
                existing_admin.is_admin = True
                existing_admin.is_active = True
                db.session.commit()
                logger.info("Admin password updated")
        else:
            # Create default admin user
            logger.info("Creating default admin user...")
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True,
                is_active=True
            )
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Default admin user created successfully")
        
        logger.info("Database initialization completed successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        try:
            db.session.rollback()
        except:
            pass
        return False

# Routes
@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            if current_user.is_admin:
                return render_template('admin_dashboard.html')
            else:
                return render_template('user_dashboard.html')
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            logger.info(f"Login attempt received: {data}")
            
            if not data:
                logger.error("No data provided in login request")
                return jsonify({'success': False, 'message': 'No data provided'}), 400
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            logger.info(f"Login attempt for username: '{username}'")
            
            if not username or not password:
                logger.warning("Username or password missing")
                return jsonify({'success': False, 'message': 'Username and password required'}), 400
            
            # Query user with exact username match
            user = User.query.filter_by(username=username).first()
            logger.info(f"User query result: {user is not None}")
            
            if user:
                logger.info(f"User found: {user.username}, Active: {user.is_active}, Admin: {user.is_admin}")
                
                if not user.is_active:
                    logger.warning(f"User {username} is inactive")
                    return jsonify({'success': False, 'message': 'Account is inactive'}), 401
                
                # Check password
                password_valid = check_password_hash(user.password_hash, password)
                logger.info(f"Password validation result: {password_valid}")
                
                if password_valid:
                    login_user(user, remember=True)
                    logger.info(f"User {username} logged in successfully")
                    return jsonify({
                        'success': True, 
                        'message': 'Login successful',
                        'redirect': '/admin' if user.is_admin else '/dashboard'
                    })
                else:
                    logger.warning(f"Invalid password for user: {username}")
            else:
                logger.warning(f"User not found: {username}")
                # Let's check all users in database for debugging
                all_users = User.query.all()
                logger.info(f"All users in database: {[(u.id, u.username) for u in all_users]}")
            
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'message': 'Login failed due to server error'}), 500
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Don't reveal if email exists or not for security
            return jsonify({'success': True, 'message': 'If the email exists, a password reset has been sent.'})
        
        # Generate new password
        new_password = generate_random_password()
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Send email with new password
        email_body = f"""
Hello {user.username},

Your password has been reset. Your new password is:

{new_password}

Please login with this password and change it immediately for security.

Best regards,
PDF Management System
        """
        
        email_sent = send_email(user.email, 'Password Reset - PDF Management System', email_body)
        
        if email_sent:
            return jsonify({'success': True, 'message': 'New password has been sent to your email.'})
        else:
            # If email fails, still save the password but inform user
            return jsonify({'success': True, 'message': 'Password reset. Contact admin if you did not receive the email.'})
            
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Password reset failed'}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'message': 'Logout failed'}), 500

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

# Folder Management Routes
@app.route('/api/folders', methods=['GET'])
@login_required
def get_folders():
    try:
        if current_user.is_admin:
            folders = Folder.query.all()
            folders_data = []
            for folder in folders:
                folders_data.append({
                    'id': folder.id,
                    'folder_name': folder.folder_name,
                    'folder_path': folder.folder_path,
                    'parent_folder_id': folder.parent_folder_id,
                    'created_at': folder.created_at.isoformat(),
                    'description': folder.description,
                    'permission_level': 'admin'
                })
        else:
            # Get folders user has permission to
            user_folders = db.session.query(Folder).join(FolderPermission).filter(
                FolderPermission.user_id == current_user.id
            ).all()
            
            folders_data = []
            for folder in user_folders:
                permission = FolderPermission.query.filter_by(
                    user_id=current_user.id,
                    folder_id=folder.id
                ).first()
                
                folders_data.append({
                    'id': folder.id,
                    'folder_name': folder.folder_name,
                    'folder_path': folder.folder_path,
                    'parent_folder_id': folder.parent_folder_id,
                    'created_at': folder.created_at.isoformat(),
                    'description': folder.description,
                    'permission_level': permission.permission_level if permission else 'view'
                })
        
        return jsonify({'folders': folders_data})
    except Exception as e:
        logger.error(f"Error getting folders: {e}")
        return jsonify({'error': 'Failed to fetch folders'}), 500

@app.route('/create_folder', methods=['POST'])
@login_required
@admin_required
def create_folder():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        folder_name = data.get('folder_name')
        parent_folder_id = data.get('parent_folder_id')
        description = data.get('description', '')
        
        if not folder_name:
            return jsonify({'success': False, 'message': 'Folder name required'}), 400
        
        # Build folder path
        if parent_folder_id:
            parent_folder = Folder.query.get(parent_folder_id)
            if not parent_folder:
                return jsonify({'success': False, 'message': 'Parent folder not found'}), 400
            folder_path = f"{parent_folder.folder_path}/{folder_name}"
        else:
            folder_path = folder_name
        
        folder = Folder(
            folder_name=folder_name,
            folder_path=folder_path,
            parent_folder_id=parent_folder_id,
            created_by=current_user.id,
            description=description
        )
        
        db.session.add(folder)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Folder created successfully'})
    except Exception as e:
        logger.error(f"Error creating folder: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to create folder'}), 500

# File Management Routes
@app.route('/folders/<int:folder_id>/files')
@login_required
def get_folder_files(folder_id):
    try:
        # Check permission
        if not current_user.is_admin and not user_has_folder_permission(current_user.id, folder_id, 'view'):
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        files = PDFFile.query.filter_by(folder_id=folder_id).all()
        files_data = []
        
        for file in files:
            files_data.append({
                'id': file.id,
                'filename': file.filename,
                'original_name': file.original_name,
                'file_size': file.file_size,
                'upload_date': file.upload_date.isoformat()
            })
        
        return jsonify({'success': True, 'files': files_data})
    except Exception as e:
        logger.error(f"Error getting folder files: {e}")
        return jsonify({'success': False, 'error': 'Failed to fetch files'}), 500

@app.route('/upload/<int:folder_id>', methods=['POST'])
@login_required
def upload_files(folder_id):
    try:
        # Check permission
        if not current_user.is_admin and not user_has_folder_permission(current_user.id, folder_id, 'write'):
            return jsonify({'error': 'Upload permission required'}), 403
        
        if not s3_client:
            return jsonify({'error': 'File upload not configured'}), 500
        
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        uploaded_count = 0
        
        for file in files:
            if file and file.filename.lower().endswith('.pdf'):
                # Generate unique filename
                file_uuid = str(uuid.uuid4())
                s3_key = f"pdfs/{folder_id}/{file_uuid}_{secure_filename(file.filename)}"
                
                # Reset file pointer
                file.seek(0)
                file_content = file.read()
                file_size = len(file_content)
                file.seek(0)
                
                # Upload to S3
                if upload_to_s3(file, s3_key):
                    # Save file record to database
                    pdf_file = PDFFile(
                        filename=f"{file_uuid}_{secure_filename(file.filename)}",
                        original_name=file.filename,
                        s3_key=s3_key,
                        folder_id=folder_id,
                        file_size=file_size,
                        uploaded_by=current_user.id
                    )
                    
                    db.session.add(pdf_file)
                    uploaded_count += 1
        
        db.session.commit()
        return jsonify({'success': True, 'uploaded': uploaded_count, 'message': f'Uploaded {uploaded_count} files'})
        
    except Exception as e:
        logger.error(f"Error uploading files: {e}")
        db.session.rollback()
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/view/<int:file_id>')
@login_required
def view_pdf(file_id):
    try:
        pdf_file = PDFFile.query.get_or_404(file_id)
        
        # Check permission
        if not current_user.is_admin and not user_has_folder_permission(current_user.id, pdf_file.folder_id, 'view'):
            return jsonify({'error': 'Access denied'}), 403
        
        return render_template('pdf_viewer.html', 
                             file_id=file_id, 
                             filename=pdf_file.original_name)
    except Exception as e:
        logger.error(f"Error viewing PDF: {e}")
        return jsonify({'error': 'Failed to view PDF'}), 500

@app.route('/pdf/<int:file_id>')
@login_required
def serve_pdf(file_id):
    """Serve PDF content directly through Flask with view-only headers"""
    try:
        pdf_file = PDFFile.query.get_or_404(file_id)
        
        # Check permission
        if not current_user.is_admin and not user_has_folder_permission(current_user.id, pdf_file.folder_id, 'view'):
            return jsonify({'error': 'Access denied'}), 403
        
        # Fetch PDF content from S3
        pdf_content = get_pdf_from_s3(pdf_file.s3_key)
        
        if pdf_content is None:
            return jsonify({'error': 'Could not retrieve PDF'}), 500
        
        # Create response with view-only headers
        response = Response(
            pdf_content,
            mimetype='application/pdf',
            headers={
                'Content-Type': 'application/pdf',
                'Content-Disposition': 'inline; filename="view-only.pdf"',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN'
            }
        )
        
        return response
    except Exception as e:
        logger.error(f"Error serving PDF: {e}")
        return jsonify({'error': 'Failed to serve PDF'}), 500

# User Management Routes (Admin only)
@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
    try:
        users = User.query.all()
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat()
            })
        return jsonify({'users': users_data})
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        is_admin = data.get('is_admin', False)
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=is_admin
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to create user'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'username' in data:
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
            user.username = data['username']
        
        if 'email' in data:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({'success': False, 'message': 'Email already exists'}), 400
            user.email = data['email']
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'is_admin' in data:
            user.is_admin = data['is_admin']
        
        if 'password' in data and data['password']:
            user.password_hash = generate_password_hash(data['password'])
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to update user'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent deleting yourself
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400
        
        # Prevent deleting the last admin
        if user.is_admin:
            admin_count = User.query.filter_by(is_admin=True, is_active=True).count()
            if admin_count <= 1:
                return jsonify({'success': False, 'message': 'Cannot delete the last admin user'}), 400
        
        # Delete user's permissions first
        FolderPermission.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to delete user'}), 500

# File Management (Admin)
@app.route('/api/files', methods=['GET'])
@login_required
@admin_required
def get_all_files():
    try:
        files = PDFFile.query.join(Folder).all()
        files_data = []
        for file in files:
            folder = Folder.query.get(file.folder_id)
            uploader = User.query.get(file.uploaded_by)
            files_data.append({
                'id': file.id,
                'original_name': file.original_name,
                'folder_name': folder.folder_name if folder else 'Unknown',
                'upload_date': file.upload_date.isoformat(),
                'uploaded_by': uploader.username if uploader else 'Unknown',
                'file_size': file.file_size
            })
        return jsonify({'files': files_data})
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({'error': 'Failed to fetch files'}), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        pdf_file = PDFFile.query.get_or_404(file_id)
        
        # Check permission
        if not current_user.is_admin and not user_has_folder_permission(current_user.id, pdf_file.folder_id, 'admin'):
            return jsonify({'error': 'Delete permission required'}), 403
        
        # Delete from S3
        if s3_client:
            try:
                s3_client.delete_object(Bucket=S3_BUCKET, Key=pdf_file.s3_key)
            except Exception as e:
                logger.error(f"Error deleting from S3: {e}")
        
        # Delete from database
        db.session.delete(pdf_file)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
    
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to delete file'}), 500

# Permission Management Routes
@app.route('/api/permissions', methods=['POST'])
@login_required
@admin_required
def grant_permission():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        folder_id = data.get('folder_id')
        permission_level = data.get('permission_level', 'read')
        
        if not all([user_id, folder_id]):
            return jsonify({'success': False, 'message': 'User ID and Folder ID required'}), 400
        
        if permission_level not in ['read', 'write', 'admin']:
            return jsonify({'success': False, 'message': 'Invalid permission level'}), 400
        
        # Check if permission already exists
        existing = FolderPermission.query.filter_by(
            user_id=user_id, 
            folder_id=folder_id
        ).first()
        
        if existing:
            existing.permission_level = permission_level
            existing.granted_by = current_user.id
            existing.granted_at = datetime.utcnow()
        else:
            permission = FolderPermission(
                user_id=user_id,
                folder_id=folder_id,
                permission_level=permission_level,
                granted_by=current_user.id
            )
            db.session.add(permission)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Permission granted successfully'})
    except Exception as e:
        logger.error(f"Error granting permission: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to grant permission'}), 500

@app.route('/api/permissions/<int:user_id>/<int:folder_id>', methods=['DELETE'])
@login_required
@admin_required
def revoke_permission(user_id, folder_id):
    try:
        permission = FolderPermission.query.filter_by(
            user_id=user_id,
            folder_id=folder_id
        ).first_or_404()
        
        db.session.delete(permission)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Permission revoked successfully'})
    except Exception as e:
        logger.error(f"Error revoking permission: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to revoke permission'}), 500

# Database initialization endpoint
@app.route('/init-database')
def manual_init_db():
    """Manual database initialization endpoint"""
    try:
        with app.app_context():
            result = init_db()
            if result:
                return jsonify({'success': True, 'message': 'Database initialized successfully. Default admin: username=admin, password=admin123'})
            else:
                return jsonify({'success': False, 'message': 'Database initialization failed'})
    except Exception as e:
        logger.error(f"Manual database initialization error: {e}")
        return jsonify({'success': False, 'message': f'Database initialization failed: {str(e)}'})

# API endpoint to get current user info
@app.route('/api/user-info')
@login_required
def get_user_info():
    try:
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin
        })
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return jsonify({'error': 'Failed to get user info'}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    try:
        db.session.rollback()
    except:
        pass
    return jsonify({'error': 'Internal server error'}), 500

# Initialize database when app starts
with app.app_context():
    success = init_db()
    if not success:
        logger.error("Failed to initialize database on startup")

if __name__ == '__main__':
    # Ensure database is initialized before running
    with app.app_context():
        init_db()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
