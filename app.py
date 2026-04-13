from flask import Flask, render_template, request, redirect, url_for, session
import sys
import qrcode
import base64
from io import BytesIO
import pyotp 
import os                      # NEW: For reading environment variables
from dotenv import load_dotenv # NEW: For loading the .env file
from twilio.rest import Client # NEW: For Twilio SMS
import smtplib                 # NEW: For Gmail
from email.message import EmailMessage

# Load the environment variables from the .env file
load_dotenv()

sys.path.append('./build')
import egan_auth

app = Flask(__name__)
# NEW: Pull the secret key securely from the .env file
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_default_key')

auth_system = egan_auth.UserManager()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    qr_code_image = None

    if request.method == 'POST':
        email = request.form['email'] 
        pwd = request.form['password']
        
        success = auth_system.register_user(email, pwd)
        
        if success:
            auth_system.generate_totp_secret(email)
            uri = auth_system.get_totp_uri(email, "Egan_Auth_Project")
            
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            qr_code_image = f"data:image/png;base64,{qr_base64}"
            
            message = "Account created! Please scan this QR code with Google Authenticator or Authy."
        else:
            message = "Email already exists. Try another."
            
    return render_template('register.html', message=message, qr_code_image=qr_code_image)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    success_message = request.args.get('success_message') 

    if request.method == 'POST':
        email = request.form['email'] 
        client_response = request.form['challenge_response'] # We read the HASH, not the password!
        challenge = session.get('login_challenge', '')
        
        # Step 1: Verify the challenge-response in C++ (R6)
        if auth_system.verify_challenge_response(email, challenge, client_response):
            session['pending_user'] = email
            return redirect(url_for('verify_2fa'))
        else:
            error_message = "Invalid email or password."
            
    # If it's a GET request (just loading the page), generate a fresh challenge
    new_challenge = auth_system.generate_challenge()
    session['login_challenge'] = new_challenge
    return render_template('login.html', error_message=error_message, success_message=success_message, challenge=new_challenge)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    error_message = None
    info_message = request.args.get('info_message') # Allow passing info messages
    email = session['pending_user']
    
    # Check what MFA methods this user has available
    has_totp = bool(auth_system.get_totp_secret(email))
    enrolled_phone = auth_system.get_phone_number(email)

    if request.method == 'POST':
        # Did they submit an SMS code or an Authenticator code?
        if 'sms_code' in request.form:
            user_code = request.form['sms_code']
            if auth_system.verify_sms_code(email, user_code):
                session.pop('pending_user', None)
                session['logged_in_user'] = email
                return redirect(url_for('dashboard'))
            else:
                error_message = "Invalid or expired SMS code."
                
        elif 'totp_code' in request.form:
            user_code = request.form['totp_code']
            secret = auth_system.get_totp_secret(email)
            totp = pyotp.TOTP(secret) if secret else None
            
            if totp and totp.verify(user_code):
                session.pop('pending_user', None)
                session['logged_in_user'] = email
                return redirect(url_for('dashboard'))
            else:
                error_message = "Invalid Authenticator code."

    return render_template('verify_2fa.html', error_message=error_message, info_message=info_message, username=email, has_totp=has_totp, phone=enrolled_phone)

@app.route('/send_sms')
def send_sms():
    if 'pending_user' not in session:
        return redirect(url_for('login'))
        
    email = session['pending_user']
    phone = auth_system.get_phone_number(email)
    
    if phone:
        code = auth_system.generate_sms_code(email)
        
        # Pull Twilio credentials securely from .env
        account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        twilio_number = os.getenv('TWILIO_PHONE_NUMBER')
        
        if account_sid and auth_token:
            try:
                client = Client(account_sid, auth_token)
                message = client.messages.create(
                    body=f"Your Egan Auth security code is: {code}",
                    from_=twilio_number,
                    to=phone
                )
                print(f"Twilio message sent! SID: {message.sid}")
            except Exception as e:
                print(f"Failed to send real SMS: {e}")
        else:
            print(f"SIMULATED SMS: To {phone} - Code: {code}")
        
    return redirect(url_for('verify_2fa', info_message=f"An SMS code has been sent to {phone}"))

##R4: Forgot Password Flow
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    message = None
    if request.method == 'POST':
        email = request.form['email']
        token = auth_system.generate_reset_token(email)
        
        message = "If an account exists for that email, a password reset link has been sent."
        
        if token:
            reset_link = url_for('reset_password', email=email, token=token, _external=True)
            
            # Pull Gmail credentials securely from .env
            sender_email = os.getenv('GMAIL_SENDER_EMAIL')
            app_password = os.getenv('GMAIL_APP_PASSWORD')
            
            if sender_email and app_password:
                msg = EmailMessage()
                msg.set_content(f"Hello,\n\nClick the link below to reset your password:\n\n{reset_link}")
                msg['Subject'] = 'Egan Auth Password Reset Request'
                msg['From'] = sender_email
                msg['To'] = email

                try:
                    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                        smtp.login(sender_email, app_password)
                        smtp.send_message(msg)
                    print(f"Real email sent successfully to {email}!")
                except Exception as e:
                    print(f"Failed to send email: {e}")
            else:
                print(f"SIMULATED EMAIL: To {email} - Link: {reset_link}")

    return render_template('forgot_password.html', message=message)


@app.route('/reset_password/<email>/<token>', methods=['GET', 'POST'])
def reset_password(email, token):
    message = None
    if request.method == 'POST':
        new_pwd = request.form['password']
        
        # Pass the token back to C++ for verification
        if auth_system.reset_password(email, token, new_pwd):
            # Success! Redirect to login with a nice message
            return redirect(url_for('login', success_message="Password reset successfully! Please log in."))
        else:
            message = "Invalid or expired reset token."

    return render_template('reset_password.html', message=message, email=email)

# ==========================================
# R10: SECURITY DASHBOARD
# ==========================================

@app.route('/dashboard')
def dashboard():
    if 'logged_in_user' not in session:
        return redirect(url_for('login'))
    
    email = session['logged_in_user']
    has_totp = bool(auth_system.get_totp_secret(email))
    enrolled_phone = auth_system.get_phone_number(email)
    success_message = request.args.get('success_message')
    
    return render_template('dashboard.html', email=email, has_totp=has_totp, phone=enrolled_phone, success_message=success_message)

@app.route('/enroll_sms', methods=['POST'])
def enroll_sms():
    if 'logged_in_user' not in session: return redirect(url_for('login'))
    email = session['logged_in_user']
    phone = request.form['phone_number']
    
    auth_system.enroll_sms(email, phone)
    return redirect(url_for('dashboard', success_message="Phone number enrolled for SMS MFA!"))

# NEW ROUTE: Change Password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'logged_in_user' not in session:
        return redirect(url_for('login'))
        
    email = session['logged_in_user']
    error_message = None
    
    if request.method == 'POST':
        old_response = request.form['challenge_response']
        new_pwd = request.form['new_password']
        challenge = session.get('change_pwd_challenge', '')
        
        # Step 1: Securely verify their old password using the R6 Handshake!
        if auth_system.verify_challenge_response(email, challenge, old_response):
            # Step 2: Update to the new password
            auth_system.update_password(email, new_pwd)
            return redirect(url_for('dashboard', success_message="Password updated successfully!"))
        else:
            error_message = "Incorrect current password."
            
    # GET Request: Generate a handshake challenge for the old password
    new_challenge = auth_system.generate_challenge()
    session['change_pwd_challenge'] = new_challenge
    return render_template('change_password.html', challenge=new_challenge, error_message=error_message)

@app.route('/logout')
def logout():
    # Clear the session securely
    session.pop('logged_in_user', None)
    return redirect(url_for('login', success_message="You have been safely logged out."))

if __name__ == '__main__':
    app.run(debug=True)