from flask import Flask, render_template, request, redirect, url_for
import sys
import qrcode
import base64
from io import BytesIO

# CRITICAL FIX: Tell Python to look inside the 'build' folder for your C++ file!
# This prevents the annoying "ModuleNotFoundError" we dealt with earlier.
sys.path.append('./build')
import egan_auth

app = Flask(__name__)

# Initialize your C++ Authentication Engine!
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
        
        # Send it to C++ to verify the Argon2id hash
        if auth_system.verify_user(user, pwd):
            # If true, show them a secure dashboard!
            return f"<h1 style='text-align:center; margin-top:50px;'>Welcome to your secure dashboard, {user}!</h1>"
        else:
            error_message = "Invalid username or password."
            
    return render_template('login.html', error_message=error_message)

if __name__ == '__main__':
    # Run the web server on port 5000
    app.run(debug=True)