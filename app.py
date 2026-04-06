from flask import Flask, render_template, request, redirect, url_for, session
import sys
import qrcode
import base64
from io import BytesIO
import pyotp  # NEW: For verifying the 6-digit code

sys.path.append('./build')
import egan_auth

app = Flask(__name__)
# NEW: Sessions require a secret key to sign the browser cookies securely
app.secret_key = 'super_secret_development_key_change_in_production' 

auth_system = egan_auth.UserManager()
# --- ROUTES ---

@app.route('/')
def home():
    # If someone goes to the home page, redirect them straight to login
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

# NEW ROUTE: Process the 6-digit code
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    # If they bypassed the login screen, kick them back
    if 'pending_user' not in session:
        return redirect(url_for('login'))

    error_message = None
    user = session['pending_user']

    if request.method == 'POST':
        user_code = request.form['totp_code']
        
        # 1. Ask C++ for the user's secret
        secret = auth_system.get_totp_secret(user)
        
        if not secret:
            error_message = "2FA is not set up for this user."
        else:
            # 2. Use Python to verify if the 6-digit code matches the time
            totp = pyotp.TOTP(secret)
            if totp.verify(user_code):
                # Success! Clear the pending state and log them in properly
                session.pop('pending_user', None)
                session['logged_in_user'] = user
                
                # CHANGED: Redirect to the new dashboard route instead of hardcoded HTML
                return redirect(url_for('dashboard'))
            else:
                error_message = "Invalid 6-digit code. Please try again."

    return render_template('verify_2fa.html', error_message=error_message, username=user)

##R4: Forgot Password Flow
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    message = None
    if request.method == 'POST':
        email = request.form['email']
        
        # 1. Ask C++ to generate a token
        token = auth_system.generate_reset_token(email)
        
        # 2. Simulate sending an email (To prevent user enumeration, we show the same message regardless)
        message = "If an account exists for that email, a password reset link has been printed to the console."
        
        if token:
            # Generate the full URL for the reset link
            reset_link = url_for('reset_password', email=email, token=token, _external=True)
            print("\n" + "="*50)
            print("SIMULATED EMAIL NOTIFICATION")
            print("="*50)
            print(f"To: {email}")
            print(f"Subject: Egan Auth Password Reset Request")
            print(f"Body: Click the link below to reset your password.")
            print(f"{reset_link}")
            print("="*50 + "\n")

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
    # If the user isn't logged in, kick them back to login
    if 'logged_in_user' not in session:
        return redirect(url_for('login'))
    
    email = session['logged_in_user']
    has_totp = bool(auth_system.get_totp_secret(email))
    
    # NEW: Allow success messages to be passed here
    success_message = request.args.get('success_message')
    
    return render_template('dashboard.html', email=email, has_totp=has_totp, success_message=success_message)

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