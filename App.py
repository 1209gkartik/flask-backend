# backend/app.py
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import sqlite3
import traceback

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

def get_db_connection():
    try:
        conn = sqlite3.connect('tasks.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        raise

def init_db():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        user_estimation INTEGER NOT NULL,
                        calculated_estimation REAL,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            print("No JSON data provided.")
            return jsonify({'error': 'Invalid JSON'}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            print(f"Missing fields: username='{username}', password='{password}'")
            return jsonify({'error': 'Username and password are required'}), 400

        conn = get_db_connection()

        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            print(f"Username '{username}' already exists.")
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        print(f"Hashed password: {hashed_password}")

        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        print(f"User '{username}' registered successfully.")
        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An internal error occurred. Please try again later.'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            print("No JSON data provided.")
            return jsonify({'error': 'Invalid JSON'}), 400

        username = data.get('username')
        password = data.get('password')
        print(f'Username: {username}, Password: {password}')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        print(f'User found: {user}')

        if user and bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity=user['id'])
            conn.close()
            return jsonify({'access_token': access_token}), 200
        else:
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An internal error occurred. Please try again later.'}), 500

@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(task) for task in tasks])

@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def add_task():
    user_id = get_jwt_identity()
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    user_estimation = data.get('user_estimation')

    if not title or not description or not isinstance(user_estimation, int):
        return jsonify({'error': 'Invalid data'}), 400

    conn = get_db_connection()
    avg_estimation = conn.execute('SELECT AVG(calculated_estimation) FROM tasks WHERE user_id = ?', (user_id,)).fetchone()[0]
    calculated_estimation = (user_estimation + (avg_estimation or 0)) / 2

    conn.execute('INSERT INTO tasks (user_id, title, description, user_estimation, calculated_estimation) VALUES (?, ?, ?, ?, ?)',
                 (user_id, title, description, user_estimation, calculated_estimation))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Task added successfully', 'calculated_estimation': calculated_estimation}), 201

@app.route('/api/users', methods=['GET'])
def list_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return jsonify([dict(user) for user in users])

if __name__ == '__main__':
    init_db()
    import os
    port = int(os.environ.get('PORT', 5000))  # Use Render's assigned port
    app.run(host='0.0.0.0', port=port, debug=True)
