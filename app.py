from flask import Flask, request, jsonify, render_template, send_file, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import boto3
from datetime import datetime
import json
from dotenv import load_dotenv
import io
from botocore.exceptions import ClientError
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=S3_REGION
)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Folder(db.Model):
    __tablename__ = 'folders'
    id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(255), nullable=False)
    folder_path = db.Column(db.String(500), nullable=False)
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)

class PDFFile(db.Model):
    __tablename__ = 'pdf_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=False)
    file_size = db.Column(db.BigInteger)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))

class FolderPermission(db.Model):
    __tablename__ = 'folder_permissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=False)
    permission_level = db.Column(db.Enum('read', 'write', 'admin', name='permission_levels'), default='read')
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Helper Functions
def user_has_folder_permission(user_id, folder_id, required_level='read'):
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
    
    levels = {'read': 1, 'write': 2, 'admin': 3}
    user_level = levels.get(permission.permission_level, 0)
    required_level_num = levels.get(required_level, 1)
    
    return user_level >= required_level_num

def upload_to_s3(file_obj, s3_key):
    try:
        s3_client.upload_fileobj(
            file_obj,
            S3_BUCKET,
            s3_key,
            ExtraArgs={'ContentType': 'application/pdf'}
        )
        return True
    except Exception as e:
        print(f"S3 upload error: {e}")
        return False

def get_pdf_from_s3(s3_key):
    """Fetch PDF content from S3 and return as bytes"""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return response['Body'].read()
    except ClientError as e:
        print(f"S3 download error: {e}")
        return None

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return render_template('admin_dashboard.html')
        else:
            return render_template('user_dashboard.html')
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return jsonify({
                'success': True, 
                'message': 'Login successful',
                'is_admin': user.is_admin,
                'redirect': '/admin' if user.is_admin else '/dashboard'
            })
        
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
    
    # New users are regular users by default, not admins
    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=False
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Registration successful'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

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

# User Management Routes (Admin only)
@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_all_users():
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

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    
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

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
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

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting the last admin
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            return jsonify({'success': False, 'message': 'Cannot delete the last admin user'}), 400
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'User deleted successfully'})

# Folder Management
@app.route('/create_folder', methods=['POST'])
@login_required
@admin_required  # Only admins can create folders
def create_folder():
    data = request.get_json()
    folder_name = data.get('folder_name')
    parent_id = data.get('parent_folder_id')
    description = data.get('description', '')
    
    # Build folder path
    if parent_id:
        parent = Folder.query.get(parent_id)
        folder_path = f"{parent.folder_path}/{folder_name}"
    else:
        folder_path = folder_name
    
    folder = Folder(
        folder_name=folder_name,
        folder_path=folder_path,
        parent_folder_id=parent_id,
        created_by=current_user.id,
        description=description
    )
    
    db.session.add(folder)
    db.session.flush()  # Get the folder ID
    
    # Grant creator admin permission
    permission = FolderPermission(
        user_id=current_user.id,
        folder_id=folder.id,
        permission_level='admin',
        granted_by=current_user.id
    )
    db.session.add(permission)
    db.session.commit()
    
    return jsonify({'success': True, 'folder_id': folder.id})

@app.route('/upload/<int:folder_id>', methods=['POST'])
@login_required
@admin_required  # Only admins can upload files
def upload_files(folder_id):
    if not user_has_folder_permission(current_user.id, folder_id, 'write'):
        return jsonify({'success': False, 'message': 'No write permission'}), 403
    
    files = request.files.getlist('files')
    uploaded_files = []
    
    for file in files:
        if file and file.filename.endswith('.pdf'):
            # Generate unique S3 key
            unique_filename = str(uuid.uuid4()) + '.pdf'
            s3_key = f"pdfs/{folder_id}/{unique_filename}"
            
            # Upload to S3
            if upload_to_s3(file, s3_key):
                # Save to database
                pdf_record = PDFFile(
                    filename=unique_filename,
                    original_name=secure_filename(file.filename),
                    s3_key=s3_key,
                    folder_id=folder_id,
                    file_size=0,  # You can get this from S3 if needed
                    uploaded_by=current_user.id
                )
                db.session.add(pdf_record)
                uploaded_files.append(pdf_record.original_name)
    
    db.session.commit()
    return jsonify({'success': True, 'uploaded': len(uploaded_files)})

# File Management (Admin only routes)
@app.route('/api/files', methods=['GET'])
@login_required
@admin_required
def get_all_files():
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

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_file(file_id):
    pdf_file = PDFFile.query.get_or_404(file_id)
    
    # Delete from S3
    try:
        s3_client.delete_object(Bucket=S3_BUCKET, Key=pdf_file.s3_key)
    except Exception as e:
        print(f"S3 deletion error: {e}")
    
    # Delete from database
    db.session.delete(pdf_file)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'File deleted successfully'})

# Permission Management
@app.route('/api/permissions', methods=['POST'])
@login_required
@admin_required
def grant_permission():
    data = request.get_json()
    user_id = data.get('user_id')
    folder_id = data.get('folder_id')
    permission_level = data.get('permission_level', 'read')
    
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

@app.route('/api/permissions/<int:user_id>/<int:folder_id>', methods=['DELETE'])
@login_required
@admin_required
def revoke_permission(user_id, folder_id):
    permission = FolderPermission.query.filter_by(
        user_id=user_id,
        folder_id=folder_id
    ).first_or_404()
    
    db.session.delete(permission)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Permission revoked successfully'})

# Regular user routes (viewing only)
@app.route('/folders/<int:folder_id>/files')
@login_required
def list_folder_files(folder_id):
    if not user_has_folder_permission(current_user.id, folder_id, 'read'):
        return jsonify({'success': False, 'message': 'No access'}), 403
    
    files = PDFFile.query.filter_by(folder_id=folder_id).all()
    file_list = []
    
    for file in files:
        file_list.append({
            'id': file.id,
            'original_name': file.original_name,
            'upload_date': file.upload_date.isoformat()
        })
    
    return jsonify({'success': True, 'files': file_list})

@app.route('/view/<int:file_id>')
@login_required
def view_pdf(file_id):
    pdf_file = PDFFile.query.get_or_404(file_id)
    
    if not user_has_folder_permission(current_user.id, pdf_file.folder_id, 'read'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Instead of pre-signed URL, serve PDF through Flask with view-only headers
    return render_template('pdf_viewer.html', 
                         file_id=file_id, 
                         filename=pdf_file.original_name)

@app.route('/pdf/<int:file_id>')
@login_required
def serve_pdf(file_id):
    """Serve PDF content directly through Flask with view-only headers"""
    pdf_file = PDFFile.query.get_or_404(file_id)
    
    if not user_has_folder_permission(current_user.id, pdf_file.folder_id, 'read'):
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

@app.route('/api/folders')
@login_required
def get_user_folders():
    if current_user.is_admin:
        # Admins see all folders
        folders = Folder.query.all()
        folders_data = []
        for folder in folders:
            folders_data.append({
                'id': folder.id,
                'folder_name': folder.folder_name,
                'folder_path': folder.folder_path,
                'permission_level': 'admin'
            })
    else:
        # Regular users only see folders they have permission for
        user_folders = db.session.query(Folder).join(
            FolderPermission
        ).filter(
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
                'permission_level': permission.permission_level
            })
    
    return jsonify({'folders': folders_data})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created - username: admin, password: admin123")
    
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
