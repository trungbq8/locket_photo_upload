from flask import Flask, render_template, request, jsonify, session
import os
import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from PIL import Image
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

LOGIN_URL = "https://locketuploader-be-render.onrender.com/locket/login"
UPLOAD_MEDIA_URL = "https://locketuploader-be-render.onrender.com/locket/upload-media"
SECRET_KEY = "WNqSuwF5Pz1Rp6FTtFwooT3ZzxgbErwl"

def derive_key_and_iv(password, salt, key_length=32, iv_length=16):
    password = password.encode()
    d = hashlib.md5(password + salt).digest()
    final_key_iv = d
    while len(final_key_iv) < (key_length + iv_length):
        d = hashlib.md5(d + password + salt).digest()
        final_key_iv += d
    return final_key_iv[:key_length], final_key_iv[key_length:key_length + iv_length]

def encrypt_cryptojs(plaintext, password):
    salt = hashlib.sha256().digest()[:8]
    key, iv = derive_key_and_iv(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    encrypted_data = b"Salted__" + salt + encrypted
    return base64.b64encode(encrypted_data).decode()

def login(email, password):
    encrypted_email = encrypt_cryptojs(email, SECRET_KEY)
    encrypted_password = encrypt_cryptojs(password, SECRET_KEY)
    
    response = requests.post(LOGIN_URL, json={"email": encrypted_email, "password": encrypted_password})
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

@app.route('/')
def index():
    return render_template('index.html', logged_in=('user_id' in session), email=session.get('email', ''))

@app.route('/login', methods=['POST'])
def login_handler():
    email = request.form.get('email')
    password = request.form.get('password')
    
    user_data = login(email, password)
    
    if user_data:
        session['user_id'] = user_data['user']['localId']
        session['id_token'] = user_data['user']['idToken']
        session['email'] = email
        return jsonify({"success": True, "email": email})
    else:
        return jsonify({"success": False, "message": "Login failed. Please check your credentials."}), 401

@app.route('/upload', methods=['POST'])
def upload_handler():
    if 'user_id' not in session or 'id_token' not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    if 'photo' not in request.files:
        return jsonify({"success": False, "message": "No file selected"}), 400
    
    file = request.files['photo']
    caption = request.form.get('caption', '')

    if file.filename == '':
        return jsonify({"success": False, "message": "No file selected"}), 400

    image = Image.open(file)
    
    if hasattr(image, '_getexif'):
        exif = image._getexif()
        if exif:
            exif = {ExifTags.TAGS.get(tag, tag): value for tag, value in exif.items()}
            if 'Orientation' in exif:
                del exif['Orientation']

    if image.mode in ("RGBA", "P"):
        image = image.convert("RGB")

    img_buffer = io.BytesIO()
    image.save(img_buffer, format="JPEG", quality=95)
    
    if img_buffer.tell() <= 1024 * 1024:
        img_buffer.seek(0)
    else:
        width, height = image.size
        while img_buffer.tell() > 1024 * 1024:
            width = int(width * 0.9)
            height = int(height * 0.9)
            image = image.resize((width, height), Image.LANCZOS)

            img_buffer = io.BytesIO()
            image.save(img_buffer, format="JPEG", quality=95)

        img_buffer.seek(0)

    # Prepare the file for upload
    files = {'images': ('compressed.jpg', img_buffer, 'image/jpeg')}
    data = {
        "caption": caption,
        "userId": session['user_id'],
        "idToken": session['id_token']
    }
    response = requests.post(UPLOAD_MEDIA_URL, files=files, data=data)

    if response.status_code == 200:
        return jsonify({"success": True, "message": "Upload successful!"})
    else:
        return jsonify({"success": False, "message": "Upload failed. Please try again."}), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

if __name__ == '__main__':
    app.run(debug=True)
