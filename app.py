
import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets  # For generating a secure secret key
import subprocess  # For executing shell commands (for SSH creation)
import json
import logging
from flask_sqlalchemy import SQLAlchemy

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure logging for debugging purposes
logging.basicConfig(level=logging.DEBUG)

# DigitalOcean API token (add your own token in the .env file)
DO_API_TOKEN = os.getenv("DO_API_TOKEN")
VPS_IP = os.getenv("VPS_IP")
VPS_ROOT_PASSWORD = os.getenv("VPS_ROOT_PASSWORD")

# Secret key for signing cookies and tokens
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(24)  # Generate a secure random 24-byte string (48 chars)
    logging.debug(f"Generated SECRET_KEY: {secret_key}")  # Optional: print the generated secret key

app.secret_key = secret_key

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")  # Default sender (email)

# Database setup (using SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Initialize Flask-Mail
mail = Mail(app)

# Initialize serializer for generating email verification tokens
serializer = URLSafeTimedSerializer(app.secret_key)

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
        
        # Simple validation check
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email.', 'error')
            return redirect(url_for('signup'))

        # Create a new user and add to database
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Generate the email verification token
        token = generate_verification_token(email)
        
        # Create verification URL with external=True to ensure it uses the full URL
        verification_url = url_for('verify_email', token=token, _external=True)

        # Send the verification email
        msg = Message('Email Verification', recipients=[email])
        msg.html = f"""
        <!DOCTYPE html>
        <html lang="en">
        ...
        </html>
        """
        try:
            mail.send(msg)
            flash('A verification email has been sent to your email address.', 'success')
        except Exception as e:
            flash('Error sending verification email. Please try again.', 'error')
            logging.error(f"Email send error: {e}")

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
    else:
        flash('Verification link is invalid or has expired.', 'error')
    return redirect(url_for('signup'))

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_user(username, password):
            return redirect(url_for('select_account_type'))
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
        logging.error(f"Token verification error: {e}")
        return None  # Token expired or invalid
    return email

# Placeholder for user authentication
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:  # Check password securely in production
        return True
    return False

# Run the Flask app
if __name__ == '__main__':
    # Create the database tables
    db.create_all()
    app.run(debug=True)
