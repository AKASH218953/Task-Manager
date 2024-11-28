import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from bson import ObjectId
from datetime import datetime

# Create Flask app
app = Flask(__name__)

# Configure MongoDB and JWT
app.config["MONGO_URI"] = "mongodb+srv://Akash:t53xMtyhiW1toBve@cluster0.nlrrn.mongodb.net/users?retryWrites=true&w=majority"
app.config["JWT_SECRET_KEY"] = "your_secret_key"  # Replace with a secure key
app.secret_key = "your_flask_secret_key"          # Add a secret key for Flask sessions

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mongo = PyMongo(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect to the login page if not logged in

# Access collections
users_collection = mongo.db.users
tasks_collection = mongo.db.tasks

# User Class
class User(UserMixin):
    def __init__(self, id, username, email, first_name, last_name):
        self.id = str(id)  # MongoDB ObjectId is converted to string
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

    @classmethod
    def get_by_id(cls, user_id):
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            return cls(user["_id"], user["username"], user["email"], user["first_name"], user["last_name"])
        return None

# User loader function (needed for flask_login)
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# Routes

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Redirect to dashboard if logged in
    return redirect(url_for('login'))  # Otherwise, redirect to login page

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if not all([first_name, last_name, email, username, password]):
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        if users_collection.find_one({"email": email}) or users_collection.find_one({"username": username}):
            flash("Email or username already in use.", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "username": username,
            "password": hashed_password
        })

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        if not username_or_email or not password:
            flash("Both username/email and password are required.", "danger")
            return redirect(url_for('login'))

        user = users_collection.find_one({
            "$or": [
                {"username": username_or_email},
                {"email": username_or_email}
            ]
        })

        if not user or not bcrypt.check_password_hash(user['password'], password):
            flash("Invalid username/email or password.", "danger")
            return redirect(url_for('login'))

        login_user(User(user["_id"], user["username"], user["email"], user["first_name"], user["last_name"]))
        flash("Logged in successfully!", "success")
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Tasks Route (Manage Tasks)
@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    if request.method == 'POST':
        task_name = request.form.get('task_name')
        task_description = request.form.get('task_description')
        deadline = request.form.get('deadline')

        if not task_name or not task_description or not deadline:
            flash("Task name, description, and deadline are required.", "danger")
            return redirect(url_for('tasks'))

        try:
            deadline_date = datetime.strptime(deadline, '%Y-%m-%d')
        except ValueError:
            flash("Invalid deadline format. Use YYYY-MM-DD.", "danger")
            return redirect(url_for('tasks'))

        tasks_collection.insert_one({
            "task_name": task_name,
            "task_description": task_description,
            "status": "pending",
            "created_at": datetime.utcnow(),
            "deadline": deadline_date,
            "user_id": current_user.id
        })

        flash("Task added successfully!", "success")
        return redirect(url_for('tasks'))

    tasks_cursor = tasks_collection.find({"user_id": current_user.id})
    tasks = list(tasks_cursor)

    # Ensure the tasks have the 'deadline' attribute before processing
    for task in tasks:
        if 'deadline' not in task:
            task['deadline'] = None  # Assign None if 'deadline' doesn't exist

    return render_template('tasks.html', tasks=tasks)

# Update Task Route
@app.route('/update_task/<task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task_name = request.form.get('task_name')
    task_description = request.form.get('task_description')
    deadline = request.form.get('deadline')

    if not task_name or not task_description or not deadline:
        flash("Task name, description, and deadline are required.", "danger")
        return redirect(url_for('tasks'))

    try:
        deadline_date = datetime.strptime(deadline, '%Y-%m-%d')
    except ValueError:
        flash("Invalid deadline format. Use YYYY-MM-DD.", "danger")
        return redirect(url_for('tasks'))

    result = tasks_collection.update_one(
        {"_id": ObjectId(task_id), "user_id": current_user.id},
        {"$set": {
            "task_name": task_name,
            "task_description": task_description,
            "deadline": deadline_date
        }}
    )

    if result.matched_count == 0:
        flash("Task not found or unauthorized.", "danger")
        return redirect(url_for('tasks'))

    flash("Task updated successfully!", "success")
    return redirect(url_for('tasks'))

# Delete Task Route
@app.route('/delete_task/<task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    result = tasks_collection.delete_one(
        {"_id": ObjectId(task_id), "user_id": current_user.id}
    )

    if result.deleted_count == 0:
        flash("Task not found or unauthorized.", "danger")
        return redirect(url_for('tasks'))

    flash("Task deleted successfully!", "success")
    return redirect(url_for('tasks'))

# Profile Route (Display and Update Profile)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')

        if not first_name or not last_name or not email:
            flash("All fields are required.", "danger")
            return redirect(url_for('profile'))

        # Check if email is already used by another user
        existing_user = users_collection.find_one({"email": email})
        if existing_user and existing_user["_id"] != ObjectId(current_user.id):
            flash("Email is already in use by another account.", "danger")
            return redirect(url_for('profile'))

        # Update user details in MongoDB
        result = users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {
                "first_name": first_name,
                "last_name": last_name,
                "email": email
            }}
        )

        if result.modified_count > 0:
            flash("Profile updated successfully!", "success")
        else:
            flash("No changes were made.", "info")

        return redirect(url_for('profile'))

    # Display the current user details
    return render_template('profile.html', user=current_user)

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Default to 5000 if not provided
    app.run(host="0.0.0.0", port=port)
    app.run(debug=True)
