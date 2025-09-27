from flask import Flask, request, render_template, session, redirect, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pdf_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    folder_name = db.Column(db.String(255), nullable=False)
    folder_path = db.Column(db.String(500))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(500))

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    permission_level = db.Column(db.String(50), default='read')

# Helper Functions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    
    if session.get('is_admin'):
        return redirect('/admin')
    else:
        return redirect('/dashboard')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password_hash, password):
        if not user.is_active:
            return jsonify({'success': False, 'message': 'Account is deactivated'})
        
        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        return jsonify({
            'success': True, 
            'user': {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            }
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

# API Routes for Folders
@app.route('/api/folders', methods=['GET'])
@admin_required
def get_folders_api():
    try:
        folders = Folder.query.all()
        folders_data = []
        for folder in folders:
            folders_data.append({
                'id': folder.id,
                'folder_name': folder.folder_name,
                'folder_path': folder.folder_path,
                'description': folder.description,
                'permission_level': 'admin',
                'created_at': folder.created_at.isoformat()
            })
        return jsonify({'success': True, 'folders': folders_data})
    except Exception as e:
        print(f"Error fetching folders: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@admin_required
def delete_folder_api(folder_id):
    try:
        # Delete all files in the folder first
        files = File.query.filter_by(folder_id=folder_id).all()
        for file in files:
            # Delete physical file
            if file.file_path and os.path.exists(file.file_path):
                try:
                    os.remove(file.file_path)
                except Exception as e:
                    print(f"Error deleting physical file: {e}")
            
            # Delete from database
            db.session.delete(file)
        
        # Delete folder permissions
        permissions = Permission.query.filter_by(folder_id=folder_id).all()
        for perm in permissions:
            db.session.delete(perm)
        
        # Delete the folder itself
        folder = Folder.query.get(folder_id)
        if folder:
            db.session.delete(folder)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Folder not found'}), 404
            
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting folder: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@admin_required
def update_folder_api(folder_id):
    try:
        folder = Folder.query.get(folder_id)
        if not folder:
            return jsonify({'success': False, 'message': 'Folder not found'}), 404
        
        data = request.get_json()
        folder.folder_name = data.get('folder_name', folder.folder_name)
        folder.folder_path = data.get('folder_path', folder.folder_path)
        
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating folder: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# API Routes for Files
@app.route('/api/files', methods=['GET'])
@admin_required
def get_files_api():
    try:
        files = db.session.query(File, Folder, User).join(Folder).join(User).all()
        files_data = []
        for file, folder, user in files:
            files_data.append({
                'id': file.id,
                'original_name': file.original_name,
                'folder_name': folder.folder_name,
                'uploaded_by': user.username,
                'upload_date': file.upload_date.isoformat()
            })
        return jsonify({'success': True, 'files': files_data})
    except Exception as e:
        print(f"Error fetching files: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@admin_required
def delete_file_api(file_id):
    try:
        file = File.query.get(file_id)
        if not file:
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        # Delete physical file
        if file.file_path and os.path.exists(file.file_path):
            try:
                os.remove(file.file_path)
            except Exception as e:
                print(f"Error deleting physical file: {e}")
        
        # Delete from database
        db.session.delete(file)
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting file: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# API Routes for Users
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users_api():
    try:
        users = User.query.all()
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat()
            })
        return jsonify({'success': True, 'users': users_data})
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user_api():
    try:
        data = request.get_json()
        
        # Check if username already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'message': 'Username already exists'})
        
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            is_admin=data.get('is_admin', False),
            is_active=data.get('is_active', True)
        )
        
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating user: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user_api(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.is_admin = data.get('is_admin', user.is_admin)
        user.is_active = data.get('is_active', user.is_active)
        
        if 'password' in data and data['password']:
            user.password_hash = generate_password_hash(data['password'])
        
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user_api(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Delete user permissions
        permissions = Permission.query.filter_by(user_id=user_id).all()
        for perm in permissions:
            db.session.delete(perm)
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Folder Management Routes
@app.route('/create_folder', methods=['POST'])
@admin_required
def create_folder():
    try:
        data = request.get_json()
        
        folder = Folder(
            folder_name=data['folder_name'],
            folder_path=data.get('folder_path'),
            description=data.get('description')
        )
        
        db.session.add(folder)
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating folder: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/folders/<int:folder_id>/files')
@admin_required
def get_folder_files(folder_id):
    try:
        files = File.query.filter_by(folder_id=folder_id).all()
        files_data = []
        for file in files:
            files_data.append({
                'id': file.id,
                'original_name': file.original_name,
                'upload_date': file.upload_date.isoformat()
            })
        return jsonify({'success': True, 'files': files_data})
    except Exception as e:
        print(f"Error fetching folder files: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/upload/<int:folder_id>', methods=['POST'])
@admin_required
def upload_files(folder_id):
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'message': 'No files provided'})
        
        files = request.files.getlist('files')
        uploaded_count = 0
        
        folder = Folder.query.get(folder_id)
        if not folder:
            return jsonify({'success': False, 'message': 'Folder not found'})
        
        for file in files:
            if file and file.filename.endswith('.pdf'):
                # Generate unique filename
                filename = secure_filename(file.filename)
                unique_filename = f"{secrets.token_hex(8)}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save file
                file.save(file_path)
                
                # Save to database
                new_file = File(
                    original_name=filename,
                    stored_name=unique_filename,
                    folder_id=folder_id,
                    user_id=session['user_id'],
                    file_path=file_path
                )
                
                db.session.add(new_file)
                uploaded_count += 1
        
        db.session.commit()
        return jsonify({'success': True, 'uploaded': uploaded_count})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error uploading files: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/view/<int:file_id>')
@login_required
def view_file(file_id):
    try:
        file = File.query.get(file_id)
        if not file:
            return "File not found", 404
        
        if file.file_path and os.path.exists(file.file_path):
            return send_file(file.file_path, as_attachment=False)
        else:
            return "File not found on disk", 404
            
    except Exception as e:
        print(f"Error viewing file: {e}")
        return "Error viewing file", 500

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        file = File.query.get(file_id)
        if not file:
            return "File not found", 404
        
        if file.file_path and os.path.exists(file.file_path):
            return send_file(file.file_path, as_attachment=True, download_name=file.original_name)
        else:
            return "File not found on disk", 404
            
    except Exception as e:
        print(f"Error downloading file: {e}")
        return "Error downloading file", 500

# Password Reset (placeholder)
@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    # This is a placeholder - you would implement actual email sending here
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if user:
        # In a real implementation, you would send an email here
        print(f"Password reset requested for {email}")
        return jsonify({'success': True, 'message': 'Password reset email sent'})
    else:
        return jsonify({'success': False, 'message': 'Email not found'})

# Permissions
@app.route('/api/permissions', methods=['POST'])
@admin_required
def grant_permission():
    try:
        data = request.get_json()
        
        # Check if permission already exists
        existing = Permission.query.filter_by(
            user_id=data['user_id'],
            folder_id=data['folder_id']
        ).first()
        
        if existing:
            existing.permission_level = data['permission_level']
        else:
            permission = Permission(
                user_id=data['user_id'],
                folder_id=data['folder_id'],
                permission_level=data['permission_level']
            )
            db.session.add(permission)
        
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        print(f"Error granting permission: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create default admin user if none exists
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: admin/admin123")

if __name__ == '__main__':
    app.run(debug=True)
