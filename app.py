import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets  # For generating a secure secret key
import subprocess  # For executing shell commands (for SSH creation)
import json

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# DigitalOcean API token (add your own token in the .env file)
DO_API_TOKEN = os.getenv("DO_API_TOKEN")
VPS_IP = os.getenv("VPS_IP")
VPS_ROOT_PASSWORD = os.getenv("VPS_ROOT_PASSWORD")

# Secret key for signing cookies and tokens
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(24)  # Generate a secure random 24-byte string (48 chars)
    print(f"Generated SECRET_KEY: {secret_key}")  # Optional: print the generated secret key

app.secret_key = secret_key

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")  # Default sender (email)

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
        flash('Your email has been verified!', 'success')
        return redirect(url_for('login'))
    else:
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
        return redirect(url_for('show_account_details', account_type=account_type, details=account_details))

    return render_template('create_account.html', account_type=account_type)

# Show Account Details in a pop-up
@app.route('/show_account_details/<account_type>/<details>')
def show_account_details(account_type, details):
    return render_template('show_account_details.html', account_type=account_type, details=details)

# Functions for creating accounts
def create_ssh_account(username, password):
    """Create SSH account logic"""
    try:
        # Example: Create an SSH user by adding a new user to the server
        subprocess.run(['useradd', '-m', username], check=True)
        subprocess.run(['echo', f'{password} | passwd --stdin {username}'], check=True)
        account_details = f"SSH Account created: Username: {username}, Password: {password}"
        return account_details
    except Exception as e:
        return f'Error creating SSH account: {str(e)}'

def create_v2ray_vmess_account(username, password):
    """Create VMess V2Ray account logic"""
    try:
        config_path = '/etc/v2ray/config.json'
        with open(config_path, 'r+') as f:
            config = json.load(f)
            config['inbounds'][0]['settings']['clients'].append({
                'id': username,
                'alterId': 64,
                'security': 'auto',
                'level': 1
            })
            f.seek(0)
            json.dump(config, f, indent=4)
        account_details = f"V2Ray VMess Account created: Username: {username}, Password: {password}"
        return account_details
    except Exception as e:
        return f'Error creating VMess account: {str(e)}'

def create_v2ray_trojan_account(username, password):
    """Create Trojan V2Ray account logic"""
    # Implementation similar to VMess
    pass

def create_v2ray_xray_account(username, password):
    """Create Xray V2Ray account logic"""
    # Implementation similar to VMess
    pass

if __name__ == '__main__':
    app.run(debug=True)
