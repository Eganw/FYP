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
    qr_code_image = None # NEW: Variable to hold our QR image

    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        
        success = auth_system.register_user(user, pwd)
        
        if success:
            # 1. Ask C++ to generate the secure secret
            auth_system.generate_totp_secret(user)
            # 2. Ask C++ to format the URI for Google Authenticator
            uri = auth_system.get_totp_uri(user, "Egan_Auth_Project")
            
            # 3. Use Python to draw the QR code in memory
            img = qrcode.make(uri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            
            # 4. Convert the image to a string so HTML can display it
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            qr_code_image = f"data:image/png;base64,{qr_base64}"
            
            message = "Account created! Please scan this QR code with Google Authenticator or Authy."
        else:
            message = "Username already exists. Try another."
            
    return render_template('register.html', message=message, qr_code_image=qr_code_image)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        
        # Step 1: Verify the password in C++
        if auth_system.verify_user(user, pwd):
            # PAUSE THE LOGIN! Save the user in a temporary session
            session['pending_user'] = user
            # Send them to the 2FA screen
            return redirect(url_for('verify_2fa'))
        else:
            error_message = "Invalid username or password."
            
    return render_template('login.html', error_message=error_message)

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
                
                return f"<h1 style='text-align:center; margin-top:50px;'>Welcome to your secure dashboard, {user}!</h1>"
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

if __name__ == '__main__':
    app.run(debug=True)