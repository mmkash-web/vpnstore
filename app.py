import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import subprocess
import json

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///users.db')  # Use SQLite as default
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(24))  # Secure key for signing cookies
db = SQLAlchemy(app)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your email
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')  # Default sender (email)

# Initialize Flask-Mail
mail = Mail(app)

# Initialize serializer for generating email verification tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Database model for users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    verified = db.Column(db.Boolean, default=False)

# Create the database tables only if the database does not already exist
with app.app_context():
    if not os.path.exists('users.db'):  # Adjust the path if necessary
        db.create_all()

# Root route, redirects to home page with options for Sign Up or Login
@app.route('/')
def home():
    return render_template('home.html')

# Sign-up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the user already exists
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Username or email already exists!', 'error')
            return redirect(url_for('signup'))

        # Create the user and add to the database
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Generate the email verification token
        token = generate_verification_token(email)
        
        # Create verification URL with external=True to ensure it uses the full URL
        verification_url = url_for('verify_email', token=token, _external=True)

        # Send the verification email with a professional design
        msg = Message('Email Verification', recipients=[email])
        msg.html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verification</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    padding: 20px;
                    color: #333;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                h2 {{
                    color: #333;
                }}
                p {{
                    font-size: 16px;
                    line-height: 1.6;
                }}
                .btn {{
                    display: inline-block;
                    padding: 12px 25px;
                    background-color: #4CAF50;
                    color: white;
                    font-size: 16px;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
                .footer {{
                    margin-top: 40px;
                    font-size: 12px;
                    color: #999;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Hello {username},</h2>
                <p>Thank you for signing up with us! To complete your registration, we need to verify your email address.</p>
                <p>Please click the button below to verify your email:</p>
                <a href="{verification_url}" class="btn">Verify Your Email</a>
                <p>If you did not sign up for this account, please ignore this email.</p>
                <div class="footer">
                    <p>Best regards,<br>Emmkash Technologies</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        try:
            mail.send(msg)
            flash('A verification email has been sent to your email address.', 'success')
        except Exception as e:
            flash('Error sending verification email. Please try again.', 'error')
            print(f"Error: {e}")

        # Redirect to pending page
        return redirect(url_for('email_verification_pending'))

    return render_template('signup.html')

# Email verification page
@app.route('/verify_email/<token>')
def verify_email(token):
    email = verify_verification_token(token)
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            user.verified = True
            db.session.commit()
            flash('Your email has been verified!', 'success')
            return redirect(url_for('login'))
    flash('Verification link is invalid or has expired.', 'error')
    return redirect(url_for('signup'))

# Email verification pending page
@app.route('/email_verification_pending')
def email_verification_pending():
    return render_template('email_verification_pending.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            if user.verified:
                return redirect(url_for('select_account_type'))
            else:
                flash('Please verify your email first.', 'error')
                return redirect(url_for('login'))
        else:
            flash('Login Failed. Check your username and password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Function to generate verification token
def generate_verification_token(email):
    return serializer.dumps(email, salt='email-verify')

# Function to verify the email token
def verify_verification_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=expiration)
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None  # Token expired or invalid
    return email

# Placeholder for user authentication
def authenticate_user(username, password):
    # Add your authentication logic here (e.g., check the database)
    return True  # For now, assuming authentication is always successful

# Main menu page after account creation
@app.route('/main_menu')
def main_menu():
    return render_template('main_menu.html')

# Account Type Selection page
@app.route('/select_account_type', methods=['GET', 'POST'])
def select_account_type():
    if request.method == 'POST':
        account_type = request.form['account_type']
        return redirect(url_for('create_account', account_type=account_type))

    return render_template('select_account_type.html')

# Account creation page
@app.route('/create_account/<account_type>', methods=['GET', 'POST'])
def create_account(account_type):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if account_type == "SSH":
            account_details = create_ssh_account(username, password)
        elif account_type == "V2Ray":
            v2ray_type = request.form['v2ray_type']
            if v2ray_type == "VMess":
                account_details = create_v2ray_vmess_account(username, password)
            elif v2ray_type == "Trojan":
                account_details = create_v2ray_trojan_account(username, password)
            elif v2ray_type == "Xray":
                account_details = create_v2ray_xray_account(username, password)

        flash(account_details, 'success')
        return redirect(url_for('main_menu'))

    return render_template('create_account.html', account_type=account_type)

# Account creation functions (SSH, V2Ray, etc.)
def create_ssh_account(username, password):
    try:
        subprocess.run(['useradd', username, '-m', '-p', password])
        return f'SSH Account created: {username}'
    except Exception as e:
        return f'Error creating SSH account: {str(e)}'

def create_v2ray_vmess_account(username, password):
    try:
        with open('/etc/v2ray/config
