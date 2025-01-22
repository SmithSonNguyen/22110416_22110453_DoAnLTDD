from flask import Flask, request, jsonify
import smtplib
import random
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Giả sử đây là database in-memory
users = {}
otp_store = {}

def send_email(recipient, subject, message):
    sender = "your_email@example.com"
    password = "your_email_password"
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, f"Subject: {subject}\n\n{message}")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/')
def home():
    return "Welcome to the API OTP server!"

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    if email in users:
        return jsonify({'message': 'Email already registered'}), 400

    # hashed_password = generate_password_hash(password, method='sha256') 
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    users[email] = {'password': hashed_password, 'verified': False}
    
    otp = random.randint(100000, 999999)
    otp_store[email] = otp

    send_email(email, 'OTP Verification', f'Your OTP is {otp}')
    
    return jsonify({'message': 'User registered. Please verify OTP sent to your email'}), 201

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data['email']
    otp = data['otp']
    
    if email not in otp_store or otp_store[email] != int(otp):
        return jsonify({'message': 'Invalid OTP'}), 400
    
    users[email]['verified'] = True
    del otp_store[email]
    
    return jsonify({'message': 'Account verified successfully'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    if email not in users or not users[email]['verified']:
        return jsonify({'message': 'Account not found or not verified'}), 400
    
    if not check_password_hash(users[email]['password'], password):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                       app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'message': 'Login successful', 'token': token}), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    
    if email not in users:
        return jsonify({'message': 'Email not registered'}), 400
    
    otp = random.randint(100000, 999999)
    otp_store[email] = otp
    send_email(email, 'Reset Password OTP', f'Your OTP is {otp}')
    
    return jsonify({'message': 'OTP sent to your email'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data['email']
    otp = data['otp']
    new_password = data['new_password']
    
    if email not in otp_store or otp_store[email] != int(otp):
        return jsonify({'message': 'Invalid OTP'}), 400
    
    # hashed_password = generate_password_hash(new_password, method='sha256')
    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

    users[email]['password'] = hashed_password
    del otp_store[email]
    
    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/api/debug/otp', methods=['GET'])
def debug_otp():
    return jsonify(otp_store)


if __name__ == '__main__':
    app.run(debug=True)
