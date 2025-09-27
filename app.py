from flask import Flask, request, jsonify, session, redirect, url_for, send_file, render_template_string
import psycopg2
import psycopg2.extras
import hashlib
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import NoCredentialsError
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configuration from environment variables
DATABASE_URL = os.environ.get('DATABASE_URL')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
S3_BUCKET = os.environ.get('S3_BUCKET')
S3_REGION = os.environ.get('S3_REGION', 'us-east-1')
FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
PORT = int(os.environ.get('PORT', 5000))

# Email configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')

# Initialize S3 client
s3_client = None
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=S3_REGION
    )

def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)

def init_db():
    """Initialize the database with required tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Folders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS folders (
                id SERIAL PRIMARY KEY,
                folder_name VARCHAR(255) NOT NULL,
                folder_path VARCHAR(500),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER REFERENCES users(id)
            )
        ''')
        
        # Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                original_name VARCHAR(255) NOT NULL,
                file_key VARCHAR(500) NOT NULL,
                folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                uploaded_by INTEGER NOT NULL REFERENCES users(id),
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size BIGINT
            )
        ''')
        
        # User permissions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_permissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
                permission_level VARCHAR(50) NOT NULL DEFAULT 'read',
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by INTEGER REFERENCES users(id),
                UNIQUE(user_id, folder_id)
            )
        ''')
        
        # Password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(255) NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user if it doesn't exist
        cursor.execute('SELECT * FROM users WHERE username = %s', ('admin',))
        if not cursor.fetchone():
            admin_password = hash_password('admin123')
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, is_admin, is_active)
                VALUES (%s, %s, %s, %s, %s)
            ''', ('admin', 'admin@example.com', admin_password, True, True))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database initialization error: {e}")

def hash_password(password):
    """Hash a password for storing"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """Verify a stored password against provided password"""
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()

def require_login(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin privileges"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT is_admin FROM users WHERE id = %s', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            
            if not user or not user[0]:
                return jsonify({'success': False, 'message': 'Admin privileges required'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'success': False, 'message': 'Database error'}), 500
    decorated_function.__name__ = f.__name__
    return decorated_function

def send_email(to_email, subject, body):
    """Send email using SMTP"""
    if not all([SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL]):
        raise Exception("Email configuration not complete")
    
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'html'))
    
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    text = msg.as_string()
    server.sendmail(SENDER_EMAIL, to_email, text)
    server.quit()

# Routes
@app.route('/')
def index():
    """Main route - redirect based on login status"""
    if 'user_id' not in session:
        return redirect('/login')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[0]:  # is_admin
            return redirect('/admin')
        else:
            return redirect('/dashboard')
    except Exception as e:
        return redirect('/login')

@app.route('/login')
def login_page():
    """Serve login page"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>PDF Management - Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; }
            .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
            button:hover { background: #0056b3; }
            .error { color: red; margin-top: 10px; }
            .success { color: green; margin-top: 10px; }
            .forgot-link { text-align: center; margin-top: 20px; }
            .forgot-link a { color: #007bff; text-decoration: none; }
            .forgot-link a:hover { text-decoration: underline; }
            .back-to-login { text-align: center; margin-top: 15px; }
            .back-to-login a { color: #6c757d; text-decoration: none; font-size: 14px; }
            .back-to-login a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="login-container" id="loginContainer">
            <h2>PDF Management System</h2>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="error" id="error-message"></div>
            <div class="forgot-link">
                <a href="#" onclick="showForgotPassword()">Forgot Password?</a>
            </div>
        </div>

        <div class="login-container" id="forgotPasswordContainer" style="display: none;">
            <h2>Reset Password</h2>
            <p style="color: #666; margin-bottom: 20px; font-size: 14px;">
                Enter your email address and we will send you instructions to reset your password.
            </p>
            <form id="forgotPasswordForm">
                <div class="form-group">
                    <label for="reset_email">Email Address:</label>
                    <input type="email" id="reset_email" name="email" required placeholder="Enter your email address">
                </div>
                <button type="submit">Send Reset Instructions</button>
            </form>
            <div class="error" id="forgot-error-message"></div>
            <div class="success" id="forgot-success-message"></div>
            <div class="back-to-login">
                <a href="#" onclick="showLogin()">← Back to Login</a>
            </div>
        </div>

        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                document.getElementById('error-message').textContent = '';
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        window.location.href = '/';
                    } else {
                        document.getElementById('error-message').textContent = data.message || 'Invalid username or password';
                    }
                } catch (error) {
                    console.error('Login error:', error);
                    document.getElementById('error-message').textContent = 'Login failed. Please try again.';
                }
            });

            document.getElementById('forgotPasswordForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const email = document.getElementById('reset_email').value;
                
                document.getElementById('forgot-error-message').textContent = '';
                document.getElementById('forgot-success-message').textContent = '';
                
                try {
                    const response = await fetch('/api/password-reset', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        document.getElementById('forgot-success-message').textContent = 
                            'Password reset instructions have been sent to your email address. Please check your inbox and follow the instructions to reset your password.';
                        document.getElementById('reset_email').value = '';
                    } else {
                        document.getElementById('forgot-error-message').textContent = 
                            data.message || 'Unable to send reset instructions. Please check your email address and try again.';
                    }
                } catch (error) {
                    console.error('Password reset error:', error);
                    document.getElementById('forgot-error-message').textContent = 
                        'Password reset service is currently unavailable. Please contact your administrator for assistance.';
                }
            });

            function showForgotPassword() {
                document.getElementById('loginContainer').style.display = 'none';
                document.getElementById('forgotPasswordContainer').style.display = 'block';
                
                document.getElementById('forgot-error-message').textContent = '';
                document.getElementById('forgot-success-message').textContent = '';
                document.getElementById('reset_email').value = '';
            }

            function showLogin() {
                document.getElementById('loginContainer').style.display = 'block';
                document.getElementById('forgotPasswordContainer').style.display = 'none';
                
                document.getElementById('error-message').textContent = '';
            }

            document.getElementById('username').addEventListener('input', function() {
                document.getElementById('error-message').textContent = '';
            });

            document.getElementById('password').addEventListener('input', function() {
                document.getElementById('error-message').textContent = '';
            });

            document.getElementById('reset_email').addEventListener('input', function() {
                document.getElementById('forgot-error-message').textContent = '';
                document.getElementById('forgot-success-message').textContent = '';
            });
        </script>
    </body>
    </html>
    '''

@app.route('/admin')
@require_admin
def admin_dashboard():
    """Serve admin dashboard"""
    try:
        with open('templates/admin_dashboard.html', 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "Admin dashboard template not found. Please create templates/admin_dashboard.html"

@app.route('/dashboard')
@require_login
def user_dashboard():
    """Serve user dashboard"""
    return "User Dashboard HTML goes here"

@app.route('/login', methods=['POST'])
def login():
    """Handle login requests"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, is_active FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[2] and verify_password(user[1], password):
            session['user_id'] = user[0]
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials or account disabled'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Database error'})

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    """Handle logout"""
    session.clear()
    return jsonify({'success': True})

@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    """Handle password reset requests"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'message': 'Email address not found'})
        
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)
        
        cursor.execute('''
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        ''', (user[0], token, expires_at))
        conn.commit()
        conn.close()
        
        reset_url = f"{request.host_url}reset-password?token={token}"
        subject = "Password Reset Request - PDF Management System"
        body = f"""
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {user[1]},</p>
            <p>You have requested to reset your password for the PDF Management System.</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not request this reset, please ignore this email.</p>
        </body>
        </html>
        """
        
        send_email(email, subject, body)
        
        return jsonify({'success': True, 'message': 'Password reset instructions sent'})
        
    except Exception as e:
        print(f"Password reset error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send reset instructions'})

@app.route('/api/users', methods=['GET'])
@require_admin
def get_users():
    """Get all users"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('''
            SELECT id, username, email, is_admin, is_active, created_at
            FROM users ORDER BY created_at DESC
        ''')
        users = cursor.fetchall()
        conn.close()
        
        return jsonify({'success': True, 'users': [dict(user) for user in users]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/users', methods=['POST'])
@require_admin
def create_user():
    """Create new user"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    is_active = data.get('is_active', True)
    
    if not all([username, email, password]):
        return jsonify({'success': False, 'message': 'Username, email, and password required'})
    
    password_hash = hash_password(password)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, is_admin, is_active)
            VALUES (%s, %s, %s, %s, %s)
        ''', (username, email, password_hash, is_admin, is_active))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User created successfully'})
    except psycopg2.IntegrityError:
        return jsonify({'success': False, 'message': 'Username or email already exists'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    """Update user"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    is_active = data.get('is_active', True)
    
    if not all([username, email]):
        return jsonify({'success': False, 'message': 'Username and email required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if password:
            password_hash = hash_password(password)
            cursor.execute('''
                UPDATE users SET username = %s, email = %s, password_hash = %s, is_admin = %s, is_active = %s
                WHERE id = %s
            ''', (username, email, password_hash, is_admin, is_active, user_id))
        else:
            cursor.execute('''
                UPDATE users SET username = %s, email = %s, is_admin = %s, is_active = %s
                WHERE id = %s
            ''', (username, email, is_admin, is_active, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except psycopg2.IntegrityError:
        return jsonify({'success': False, 'message': 'Username or email already exists'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    """Delete user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/folders', methods=['GET'])
@require_login
def get_folders():
    """Get all folders"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('''
            SELECT f.id, f.folder_name, f.folder_path, f.description, f.created_at,
                   CASE WHEN up.permission_level IS NOT NULL THEN up.permission_level ELSE 'none' END as permission_level
            FROM folders f
            LEFT JOIN user_permissions up ON f.id = up.folder_id AND up.user_id = %s
            ORDER BY f.created_at DESC
        ''', (session['user_id'],))
        folders = cursor.fetchall()
        conn.close()
        
        return jsonify({'success': True, 'folders': [dict(folder) for folder in folders]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/create_folder', methods=['POST'])
@require_admin
def create_folder():
    """Create new folder"""
    data = request.get_json()
    folder_name = data.get('folder_name')
    folder_path = data.get('folder_path')
    description = data.get('description')
    
    if not folder_name:
        return jsonify({'success': False, 'message': 'Folder name required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO folders (folder_name, folder_path, description, created_by)
            VALUES (%s, %s, %s, %s)
        ''', (folder_name, folder_path, description, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Folder created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/folders/<int:folder_id>', methods=['PUT'])
@require_admin
def update_folder(folder_id):
    """Update folder"""
    data = request.get_json()
    folder_name = data.get('folder_name')
    folder_path = data.get('folder_path')
    
    if not folder_name:
        return jsonify({'success': False, 'message': 'Folder name required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE folders SET folder_name = %s, folder_path = %s
            WHERE id = %s
        ''', (folder_name, folder_path, folder_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Folder updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@require_admin
def delete_folder(folder_id):
    """Delete folder and all its files"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT file_key FROM files WHERE folder_id = %s', (folder_id,))
        files = cursor.fetchall()
        
        if s3_client and files:
            for file in files:
                try:
                    s3_client.delete_object(Bucket=S3_BUCKET, Key=file[0])
                except Exception as e:
                    print(f"Error deleting file from S3: {e}")
        
        cursor.execute('DELETE FROM folders WHERE id = %s', (folder_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Folder deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/files', methods=['GET'])
@require_login
def get_files():
    """Get all files user has access to"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('''
            SELECT f.id, f.original_name, f.upload_date, f.file_size,
                   fo.folder_name, u.username as uploaded_by
            FROM files f
            JOIN folders fo ON f.folder_id = fo.id
            JOIN users u ON f.uploaded_by = u.id
            LEFT JOIN user_permissions up ON fo.id = up.folder_id AND up.user_id = %s
            WHERE up.permission_level IS NOT NULL OR u.id = %s
            ORDER BY f.upload_date DESC
        ''', (session['user_id'], session['user_id']))
        files = cursor.fetchall()
        conn.close()
        
        return jsonify({'success': True, 'files': [dict(file) for file in files]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@require_login
def delete_file(file_id):
    """Delete a file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT file_key FROM files WHERE id = %s', (file_id,))
        file = cursor.fetchone()
        
        if file:
            if s3_client:
                try:
                    s3_client.delete_object(Bucket=S3_BUCKET, Key=file[0])
                except Exception as e:
                    print(f"Error deleting file from S3: {e}")
            
            cursor.execute('DELETE FROM files WHERE id = %s', (file_id,))
            conn.commit()
        
        conn.close()
        return jsonify({'success': True, 'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/folders/<int:folder_id>/files', methods=['GET'])
@require_login
def get_folder_files(folder_id):
    """Get files in a specific folder"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute('''
            SELECT f.id, f.original_name, f.upload_date, f.file_size
            FROM files f
            WHERE f.folder_id = %s
            ORDER BY f.upload_date DESC
        ''', (folder_id,))
        files = cursor.fetchall()
        conn.close()
        
        return jsonify({'success': True, 'files': [dict(file) for file in files]})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/upload/<int:folder_id>', methods=['POST'])
@require_login
def upload_files(folder_id):
    """Upload files to a folder"""
    if 'files' not in request.files:
        return jsonify({'success': False, 'message': 'No files provided'})
    
    files = request.files.getlist('files')
    uploaded_count = 0
    errors = []
    
    for file in files:
        if file.filename == '':
            continue
            
        if not file.filename.lower().endswith('.pdf'):
            errors.append(f"{file.filename}: Only PDF files allowed")
            continue
        
        try:
            file_key = f"{folder_id}/{uuid.uuid4()}_{secure_filename(file.filename)}"
            
            if s3_client:
                s3_client.upload_fileobj(file, S3_BUCKET, file_key)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (original_name, file_key, folder_id, uploaded_by, file_size)
                VALUES (%s, %s, %s, %s, %s)
            ''', (file.filename, file_key, folder_id, session['user_id'], file.content_length or 0))
            conn.commit()
            conn.close()
            
            uploaded_count += 1
            
        except Exception as e:
            errors.append(f"{file.filename}: {str(e)}")
    
    return jsonify({
        'success': uploaded_count > 0,
        'uploaded': uploaded_count,
        'errors': errors,
        'message': f'Uploaded {uploaded_count} files'
    })

@app.route('/view/<int:file_id>')
@require_login
def view_file(file_id):
    """View/serve a file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.file_key, f.original_name, fo.id
            FROM files f
            JOIN folders fo ON f.folder_id = fo.id
            LEFT JOIN user_permissions up ON fo.id = up.folder_id AND up.user_id = %s
            WHERE f.id = %s AND (up.permission_level IS NOT NULL OR f.uploaded_by = %s)
        ''', (session['user_id'], file_id, session['user_id']))
        file = cursor.fetchone()
        conn.close()
        
        if not file:
            return jsonify({'error': 'File not found or access denied'}), 404
        
        file_key, original_name, folder_id = file
        
        if s3_client:
            try:
                url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': S3_BUCKET, 'Key': file_key},
                    ExpiresIn=3600
                )
                return redirect(url)
            except Exception as e:
                return jsonify({'error': 'File access error'}), 500
        else:
            return jsonify({'error': 'File storage not configured'}), 500
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/download/<int:file_id>')
@require_login
def download_file(file_id):
    """Download a file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.file_key, f.original_name, fo.id
            FROM files f
            JOIN folders fo ON f.folder_id = fo.id
            LEFT JOIN user_permissions up ON fo.id = up.folder_id AND up.user_id = %s
            WHERE f.id = %s AND (up.permission_level IS NOT NULL OR f.uploaded_by = %s)
        ''', (session['user_id'], file_id, session['user_id']))
        file = cursor.fetchone()
        conn.close()
        
        if not file:
            return jsonify({'error': 'File not found or access denied'}), 404
        
        file_key, original_name, folder_id = file
        
        if s3_client:
            try:
                url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': S3_BUCKET, 
                        'Key': file_key,
                        'ResponseContentDisposition': f'attachment; filename="{original_name}"'
                    },
                    ExpiresIn=3600
                )
                return redirect(url)
            except Exception as e:
                return jsonify({'error': 'File download error'}), 500
        else:
            return jsonify({'error': 'File storage not configured'}), 500
    except Exception as e:
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/permissions', methods=['POST'])
@require_admin
def grant_permission():
    """Grant folder permission to user"""
    data = request.get_json()
    user_id = data.get('user_id')
    folder_id = data.get('folder_id')
    permission_level = data.get('permission_level', 'read')
    
    if not all([user_id, folder_id]):
        return jsonify({'success': False, 'message': 'User ID and Folder ID required'})
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_permissions 
            (user_id, folder_id, permission_level, granted_by)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id, folder_id) 
            DO UPDATE SET permission_level = EXCLUDED.permission_level,
                         granted_by = EXCLUDED.granted_by,
                         granted_at = CURRENT_TIMESTAMP
        ''', (user_id, folder_id, permission_level, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Permission granted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/permissions/<int:user_id>/<int:folder_id>', methods=['DELETE'])
@require_admin
def revoke_permission(user_id, folder_id):
    """Revoke folder permission from user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM user_permissions 
            WHERE user_id = %s AND folder_id = %s
        ''', (user_id, folder_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Permission revoked successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/reset-password')
def reset_password_page():
    """Serve password reset page"""
    token = request.args.get('token')
    if not token:
        return "Invalid reset link", 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT prt.user_id, u.username 
            FROM password_reset_tokens prt
            JOIN users u ON prt.user_id = u.id
            WHERE prt.token = %s AND prt.expires_at > NOW() AND prt.used = FALSE
        ''', (token,))
        token_data = cursor.fetchone()
        conn.close()
        
        if not token_data:
            return "Invalid or expired reset link", 400
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reset Password - PDF Management</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
                .reset-container {{ max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .form-group {{ margin-bottom: 20px; }}
                label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
                input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
                button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
                button:hover {{ background: #0056b3; }}
                .error {{ color: red; margin-top: 10px; }}
                .success {{ color: green; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="reset-container">
                <h2>Reset Password</h2>
                <p>Reset password for: <strong>{token_data[1]}</strong></p>
                <form id="resetForm">
                    <input type="hidden" id="token" value="{token}">
                    <div class="form-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password" required minlength="6">
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password:</label>
                        <input type="password" id="confirm_password" name="confirm_password" required minlength="6">
                    </div>
                    <button type="submit">Reset Password</button>
                </form>
                <div class="error" id="error-message"></div>
                <div class="success" id="success-message"></div>
            </div>

            <script>
                document.getElementById('resetForm').addEventListener('submit', async (e) => {{
                    e.preventDefault();
                    
                    const token = document.getElementById('token').value;
                    const newPassword = document.getElementById('new_password').value;
                    const confirmPassword = document.getElementById('confirm_password').value;
                    
                    document.getElementById('error-message').textContent = '';
                    document.getElementById('success-message').textContent = '';
                    
                    if (newPassword !== confirmPassword) {{
                        document.getElementById('error-message').textContent = 'Passwords do not match';
                        return;
                    }}
                    
                    if (newPassword.length < 6) {{
                        document.getElementById('error-message').textContent = 'Password must be at least 6 characters';
                        return;
                    }}
                    
                    try {{
                        const response = await fetch('/api/reset-password', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token, new_password: newPassword }})
                        }});
                        
                        const data = await response.json();
                        
                        if (data.success) {{
                            document.getElementById('success-message').textContent = 'Password reset successfully! You can now login with your new password.';
                            document.getElementById('resetForm').style.display = 'none';
                            setTimeout(() => {{
                                window.location.href = '/login';
                            }}, 3000);
                        }} else {{
                            document.getElementById('error-message').textContent = data.message || 'Error resetting password';
                        }}
                    }} catch (error) {{
                        console.error('Reset error:', error);
                        document.getElementById('error-message').textContent = 'Error resetting password. Please try again.';
                    }}
                }});
            </script>
        </body>
        </html>
        '''
    except Exception as e:
        return "Database error", 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password_confirm():
    """Confirm password reset"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Token and new password required'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id FROM password_reset_tokens 
            WHERE token = %s AND expires_at > NOW() AND used = FALSE
        ''', (token,))
        token_data = cursor.fetchone()
        
        if not token_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid or expired token'})
        
        user_id = token_data[0]
        
        password_hash = hash_password(new_password)
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (password_hash, user_id))
        
        cursor.execute('UPDATE password_reset_tokens SET used = TRUE WHERE token = %s', (token,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=(FLASK_ENV == 'development'))
