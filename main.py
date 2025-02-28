from flask import Flask, render_template, jsonify, request, redirect, url_for, session  # Add session import
import os
import requests
import logging
import cv2
from ultralytics import YOLO
from geopy.geocoders import Nominatim
import uuid
import base64
import bcrypt  # Add bcrypt import
from functools import wraps  # Add wraps import for login_required decorator
from geopy.distance import geodesic  # Add geodesic import for distance calculation

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Add a secret key for session management

SUPABASE_URL = 'https://*********.supabase.co'
SUPABASE_KEY = '********'
CENTRAL_WALLET_PRIVATE_KEY = '*********************'
CENTRAL_WALLET_ADDRESS = '86014fa7a3efecfb521600b55616e4aca9ad754de7772e4ea6a9c93da7889602'

logging.basicConfig(level=logging.DEBUG)

# Ensure the static/images directory exists
os.makedirs('static/images', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/redeem')
def connect_wallet():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('connect_wallet.html', central_wallet_address=CENTRAL_WALLET_ADDRESS)

@app.route('/leaderboard')
def leaderboard():
    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Leaderboard', headers=headers)
    data = response.json()
    return jsonify(data)

@app.route('/add-player', methods=['GET', 'POST'])
def add_player():
    if request.method == 'GET':
        return render_template('add_player.html')
    elif request.method == 'POST':
        data = request.json
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': 'application/json'
        }
        payload = {
            'Username': data['username'],
            'Rank': data['rank'],
            'Score': data['points']
        }
        response = requests.post(f'{SUPABASE_URL}/rest/v1/Leaderboard', headers=headers, json=payload)
        logging.debug(f'Supabase response status: {response.status_code}')
        logging.debug(f'Supabase response body: {response.text}')
        if response.status_code == 201:
            return jsonify({'message': 'Player added successfully!'}), 201
        else:
            return jsonify({'message': 'Failed to add player.'}), 400

@app.route('/capture-image')
def capture_image():
    return render_template('capture_image.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        next_url = request.args.get('next', url_for('index'))

        logging.info(f'Login attempt with email: {email}')

        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}'
        }
        response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
        if response.status_code == 200 and response.json():
            user = response.json()[0]
            stored_hash = user['Hash']
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                session['user'] = email  # Store user email in session
                key = email + "+" + password
                key = base64.b64encode(key.encode()).decode()
                return render_template('key.html', key=key, next_url=next_url)
            else:
                return jsonify({'message': 'Invalid email or password.'}), 401
        else:
            return jsonify({'message': 'Invalid email or password.'}), 401

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        logging.info(f'Sign-up attempt with email: {email}')
        
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': 'application/json'
        }
        payload = {
            'Email': email,
            'Hash': hashed_password
        }
        response = requests.post(f'{SUPABASE_URL}/rest/v1/Users', headers=headers, json=payload)
        logging.debug(f'Supabase response status: {response.status_code}')
        logging.debug(f'Supabase response body: {response.text}')
        
        if response.status_code == 201:
            session['user'] = email  # Store user email in session
            return redirect(url_for('index'))
        else:
            return jsonify({'message': 'Failed to sign up user.'}), 400

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove user from session
    return redirect(url_for('index'))

@app.route('/get-xp', methods=['POST'])
def get_xp():
    data = request.json
    key = data.get('key')
    email, password = base64.b64decode(key).decode().split('+')

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return jsonify({'xp': user['xp']}), 200
        else:
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        return jsonify({'message': 'Invalid key.'}), 401

@app.route('/update-xp', methods=['POST'])
def update_xp():
    data = request.json
    key = data.get('key')
    new_xp = data.get('xp')
    email, password = base64.b64decode(key).decode().split('+')

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            update_payload = {'xp': new_xp}
            update_response = requests.patch(f'{SUPABASE_URL}/rest/v1/Users?id=eq.{user["id"]}', headers=headers, json=update_payload)
            if update_response.status_code == 204:
                return jsonify({'message': 'XP updated successfully!'}), 200
            else:
                return jsonify({'message': 'Failed to update XP.'}), 400
        else:
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        return jsonify({'message': 'Invalid key.'}), 401

@app.route('/validate-key', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    
    logging.debug(f"Received key for validation: {key}")

    if not key:
        logging.error("Key is missing in the request.")
        return jsonify({'valid': False, 'message': 'Key is missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'valid': False, 'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return jsonify({'valid': True}), 200
        else:
            logging.error("Invalid key: Password does not match.")
            return jsonify({'valid': False, 'message': 'Invalid key.'}), 401
    else:
        logging.error("Invalid key: User not found or other error.")
        return jsonify({'valid': False, 'message': 'Invalid key.'}), 401

@app.route('/rewards', methods=['POST'])
def rewards():
    data = request.json
    key = data.get('key')
    
    logging.debug(f"Received key for rewards: {key}")

    if not key:
        logging.error("Key is missing in the request.")
        return jsonify({'message': 'Key is missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            rewards_response = requests.get(f'{SUPABASE_URL}/rest/v1/Rewards?email=eq.{email}', headers=headers)
            if rewards_response.status_code == 200:
                rewards = rewards_response.json()
                reward_ids = [reward['reward_id'] for reward in rewards]
                return jsonify({'reward_ids': reward_ids}), 200
            else:
                logging.error("Failed to fetch rewards.")
                return jsonify({'message': 'Failed to fetch rewards.'}), 400
        else:
            logging.error("Invalid key: Password does not match.")
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        logging.error("Invalid key: User not found or other error.")
        return jsonify({'message': 'Invalid key.'}), 401

@app.route('/check-reward', methods=['POST'])
def check_reward():
    data = request.json
    key = data.get('key')
    reward_id = data.get('reward_id')
    
    logging.debug(f"Received key for reward check: {key} and reward_id: {reward_id}")

    if not key or not reward_id:
        logging.error("Key or reward_id is missing in the request.")
        return jsonify({'valid': False, 'message': 'Key or reward_id is missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'valid': False, 'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/rewards?email=eq.{email}&reward_id=eq.{reward_id}', headers=headers)
    if response.status_code == 200 and response.json():
        print(response.json())
        return jsonify({'valid': True}), 200
    else:
        print(response.json())
        return jsonify({'valid': False}), 200

@app.route('/add-reward', methods=['POST'])
def add_reward():
    data = request.json
    key = data.get('key')
    reward_id = data.get('reward_id')
    
    logging.debug(f"Received key for adding reward: {key} and reward_id: {reward_id}")

    if not key or not reward_id:
        logging.error("Key or reward_id is missing in the request.")
        return jsonify({'message': 'Key or reward_id is missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # Check if the reward already exists
            check_response = requests.get(f'{SUPABASE_URL}/rest/v1/rewards?email=eq.{email}&reward_id=eq.{reward_id}', headers=headers)
            if check_response.status_code == 200 and check_response.json():
                logging.info("Reward already exists for this user.")
                return jsonify({'message': 'Reward already exists.'}), 200
            
            # Add the reward if it does not exist
            payload = {
                'email': email,
                'reward_id': reward_id
            }
            reward_response = requests.post(f'{SUPABASE_URL}/rest/v1/rewards', headers=headers, json=payload)
            logging.debug(f'Supabase response status: {reward_response.status_code}')
            logging.debug(f'Supabase response body: {reward_response.text}')
            if reward_response.status_code == 201:
                return jsonify({'message': 'Reward added successfully!'}), 201
            else:
                logging.error("Failed to add reward.")
                return jsonify({'message': 'Failed to add reward.'}), 400
        else:
            logging.error("Invalid key: Password does not match.")
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        logging.error("Invalid key: User not found or other error.")
        return jsonify({'message': 'Invalid key.'}), 401

@app.route('/get-unclaimed-coins')
@login_required
def get_unclaimed_coins():
    email = session['user']
    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        unclaimed_coins = user.get('unclaimed_coins', 0)
        return jsonify({'unclaimed_coins': unclaimed_coins}), 200
    else:
        return jsonify({'unclaimed_coins': 0}), 400

@app.route('/update-unclaimed-coins', methods=['POST'])
@login_required
def update_unclaimed_coins():
    email = session['user']
    data = request.json
    new_unclaimed_coins = data.get('unclaimed_coins')

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'unclaimed_coins': new_unclaimed_coins
    }
    response = requests.patch(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers, json=payload)
    if response.status_code == 204:
        return jsonify({'message': 'Unclaimed coins updated successfully!'}), 200
    else:
        return jsonify({'message': 'Failed to update unclaimed coins.'}), 400

@app.route('/add-coins', methods=['POST'])
def add_coins():
    data = request.json
    logging.debug(f"Received data: {data}")
    key = data.get('key')
    coins_to_add = data.get('coins')

    logging.debug(f"Received key for adding coins: {key} and coins: {coins_to_add}")

    if not key or coins_to_add is None:
        logging.error("Key or coins are missing in the request.")
        return jsonify({'message': 'Key or coins are missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            new_coin_balance = user.get('unclaimed_coins', 0) + coins_to_add
            payload = {'unclaimed_coins': new_coin_balance}
            update_response = requests.patch(f'{SUPABASE_URL}/rest/v1/Users?id=eq.{user["id"]}', headers=headers, json=payload)
            if update_response.status_code == 204:
                return jsonify({'message': 'Coins added successfully!'}), 200
            else:
                logging.error("Failed to add coins.")
                return jsonify({'message': 'Failed to add coins.'}), 400
        else:
            logging.error("Invalid key: Password does not match.")
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        logging.error("Invalid key: User not found or other error.")
        return jsonify({'message': 'Invalid key.'}), 401

@app.route('/get-coins', methods=['POST'])
def get_coins():
    data = request.json
    key = data.get('key')

    logging.debug(f"Received key for getting coins: {key}")

    if not key:
        logging.error("Key is missing in the request.")
        return jsonify({'message': 'Key is missing.'}), 400

    try:
        email, password = base64.b64decode(key).decode().split('+')
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        return jsonify({'message': 'Invalid key format.'}), 400

    headers = {
        'apikey': SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}'
    }
    response = requests.get(f'{SUPABASE_URL}/rest/v1/Users?Email=eq.{email}', headers=headers)
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        stored_hash = user['Hash']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            unclaimed_coins = user.get('unclaimed_coins', 0)
            return jsonify({'coins': unclaimed_coins}), 200
        else:
            logging.error("Invalid key: Password does not match.")
            return jsonify({'message': 'Invalid key.'}), 401
    else:
        logging.error("Invalid key: User not found or other error.")
        return jsonify({'message': 'Invalid key.'}), 401

def run_inference(image_path):
    model = YOLO("runs/detect/train/yolov8s_100epochs/weights/best.pt")
    results = model.predict(source=image_path, save=True)

    total_trash_items = 0  # Initialize counter for trash items

    for result in results:
        frame = result.orig_img
        for box in result.boxes:
            x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())  # Flatten the list
            label = int(box.cls)  # Convert tensor to int
            confidence = float(box.conf)  # Convert tensor to float
            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.putText(frame, f"{label} {confidence:.2f}", (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
            total_trash_items += 1  # Increment counter for each detected item
        
        # Generate a unique name for the highlighted image
        unique_filename = f"{uuid.uuid4()}.jpg"
        output_path = os.path.join('static/images', unique_filename)
        cv2.imwrite(output_path, frame)
        return unique_filename, total_trash_items  # Return the unique filename and garbage amount

@app.route('/upload-image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        logging.error('No image part in the request')
        return jsonify({'message': 'No image part'}), 400
    file = request.files['image']
    hazardous = request.form.get('hazardous') == 'true'
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    if file.filename == '':
        logging.error('No selected file')
        return jsonify({'message': 'No selected file'}), 400
    if file:
        filename = file.filename
        file_path = os.path.join('static/images', filename)
        file.save(file_path)
        logging.info(f"File saved to: {file_path}")
        
        # Run inference on the uploaded image
        unique_filename, garbage_amount = run_inference(file_path)
        unique_file_path = os.path.join('static/images', unique_filename)
        logging.info(f"Output saved to {unique_file_path}")
        logging.info(f"Total trash items detected: {garbage_amount}")
        
        # Store report in the Reports table
        coordinates = f"{latitude},{longitude}"
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': 'application/json'
        }
        payload = {
            'Coordinates': coordinates,
            'Hazards': hazardous,
            'Cleaned': False,
            'ImageURL': f'/static/images/{unique_filename}'  # Local link to the image
        }
        response = requests.post(f'{SUPABASE_URL}/rest/v1/Reports', headers=headers, json=payload)
        logging.debug(f'Supabase response status: {response.status_code}')
        logging.debug(f'Supabase response body: {response.text}')
        
        return jsonify({
            'message': 'Image uploaded successfully!',
            'highlighted_image_url': f'/static/images/{unique_filename}',  # Local link to the image
            'garbage_amount': garbage_amount
        }), 201

@app.route('/clean-garbage', methods=['GET', 'POST'])
@login_required
def clean_garbage():
    if request.method == 'GET':
        return render_template('clean_garbage.html')
    elif request.method == 'POST':
        if 'image' not in request.files:
            logging.error('No image part in the request')
            return jsonify({'message': 'No image part'}), 400
        file = request.files['image']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        if file.filename == '':
            logging.error('No selected file')
            return jsonify({'message': 'No selected file'}), 400
        if file:
            filename = file.filename
            file_path = os.path.join('static/images', filename)
            file.save(file_path)
            logging.info(f"File saved to: {file_path}")
            
            # Run inference on the uploaded image
            unique_filename, garbage_amount = run_inference(file_path)
            unique_file_path = os.path.join('static/images', unique_filename)
            logging.info(f"Output saved to {unique_file_path}")
            logging.info(f"Total trash items detected: {garbage_amount}")
            
            # Find the nearest garbage report within 5km
            headers = {
                'apikey': SUPABASE_KEY,
                'Authorization': f'Bearer {SUPABASE_KEY}'
            }
            response = requests.get(f'{SUPABASE_URL}/rest/v1/Reports', headers=headers)
            reports = response.json()
            user_location = (float(latitude), float(longitude))
            nearest_report = None
            min_distance = float('inf')
            for report in reports:
                report_coords = tuple(map(float, report['Coordinates'].split(',')))
                distance = geodesic(user_location, report_coords).km
                if distance <= 5 and distance < min_distance:
                    nearest_report = report
                    min_distance = distance
            
            if nearest_report:
                # Mark the nearest report as cleaned
                report_id = nearest_report['id']
                update_payload = {'Cleaned': True}
                update_response = requests.patch(f'{SUPABASE_URL}/rest/v1/Reports?id=eq.{report_id}', headers=headers, json=update_payload)
                if update_response.status_code == 204:
                    logging.info(f"Report {report_id} marked as cleaned.")
                else:
                    logging.error(f"Failed to mark report {report_id} as cleaned.")
            
            return jsonify({
                'message': 'Image uploaded successfully!',
                'highlighted_image_url': f'/static/images/{unique_filename}',  # Local link to the image
                'garbage_amount': garbage_amount
            }), 201

if __name__ == '__main__':
    import os
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(app.wsgi_app)

    # Ignore changes in the site-packages and static/images directories
    extra_files = []
    for root, dirs, files in os.walk(os.path.dirname(__file__)):
        if 'static/images' in root:
            continue
        for file in files:
            extra_files.append(os.path.join(root, file))

    app.run(debug=True, host='0.0.0.0', port=5002, extra_files=extra_files, use_reloader=False)
