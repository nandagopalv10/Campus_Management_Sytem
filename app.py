# Importing necessary modules and libraries
from flask import Flask, render_template, request, redirect, url_for, session ,flash # Flask (for creating the web application), render_template (for rendering HTML templates),                                                                                      # request (for handling HTTP requests), redirect and url_for (for redirecting to other routes or URLs),                                                                                     # session (for managing user sessions), and flash (for displaying messages to the user).
import sqlite3 # Importing SQLite for database operations
import os # Importing os for miscellaneous operating system interfaces
import bcrypt # Importing bcrypt for password hashing
import json # Importing json for working with JSON data
import requests # Importing requests for making HTTP requests
from PIL import Image, ImageDraw, ImageFont # Importing modules for working with images
import random # Importing random for generating random values
import io # Importing io for working with streams and bytes
import base64 # Importing base64 for encoding and decoding base64 data
from flask_mail import Mail, Message # Importing the Mail and Message classes from Flask-Mail

app = Flask(__name__) # Creating a Flask application instance
app.secret_key = os.urandom(24) # Generating a random 24-byte string that serves as the secret key for the application 
app.static_url_path = '/static' # Setting the URL path for static files to /static

DATABASE = "database.db" # Setting the name of the SQLite database file
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY') # Getting the reCAPTCHA secret key from environment variables

# Initializing the SQLite database for the application
# Define a function named init_db to set up the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

     # Check if the phone_number column exists in the students table
    cursor.execute("PRAGMA table_info(students)")
    columns = cursor.fetchall()
    phone_number_exists = any(column[1] == 'phone_number' for column in columns)
    new_phone_number_request_exists = any(column[1] == 'new_phone_number_request' for column in columns)


    if not phone_number_exists:
        # Alter the students table to add the phone_number column if it doesn't exist
        cursor.execute("ALTER TABLE students ADD COLUMN phone_number TEXT")

    if not new_phone_number_request_exists:
        # Alter the students table to add the new_phone_number_request column if it doesn't exist
        cursor.execute("ALTER TABLE students ADD COLUMN new_phone_number_request TEXT")

    # Create users table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Create students table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            email TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            new_phone_number_request TEXT
        )
    ''')

    # Create teachers table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            employee_id TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    # Create courses table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY,
            course_code TEXT NOT NULL,
            course_name TEXT NOT NULL
        )
    ''')
    # Create courses table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS teacher_student_assignment (
            id INTEGER PRIMARY KEY,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers (id),
            FOREIGN KEY (student_id) REFERENCES students (id)
                   
        )
    ''')

    # Check if there is an admin user in the 'users' table
    cursor.execute("SELECT * FROM users WHERE role='admin'")
    admin_user = cursor.fetchone()

    # If there is no admin user, create one with default credentials
    if not admin_user:
        admin_username = "admin"
        admin_password = "admin"
        admin_role = "admin"

        hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                       (admin_username, hashed_admin_password, admin_role))

    conn.commit()
    conn.close()



# Define a route for the root URL
@app.route('/')

def welcome():
    return render_template('welcome.html')

# Define a function to be executed when a user visits the root 
def index():
    return redirect(url_for('login')) # Redirect to the 'login' route

# Define a function to generate a random CAPTCHA
def generate_captcha():
    captcha = ''.join(random.choice('0123456789') for _ in range(4)) # Generate a random 4-digit CAPTCHA
    return captcha


def verify_recaptcha(recaptcha_response):
    secret_key = "6LddK48oAAAAAOTdkykCV11V2uz_LP1if2jelHCK"
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)


# Define a function to generate a CAPTCHA image with distortion
def generate_captcha_image(text):
    width, height = 180, 150  # Set the dimensions of the image

    image = Image.new("RGB", (width, height), "white") # Create a new white image
    draw = ImageDraw.Draw(image)

    font = ImageFont.truetype("static/fonts/montserrat/Montserrat-BlackItalic.ttf", 30) # Use the default font that comes with Pillow
    draw.text((100, 40), text, font=font, fill=(0, 0, 0)) # Draw the CAPTCHA text on the image

    # Apply distortion to the image
    for _ in range(100):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = x1 + random.randint(0, 180)
        y2 = y1 + random.randint(0, 180)
        draw.line((x1, y1, x2, y2), fill=(0, 0, 0))

    # Save the image in memory
    image_io = io.BytesIO()
    image.save(image_io, "PNG")
    image_io.seek(0)
    return image_io

# Define a function to generate a random recovery token
def generate_recovery_token():
    # Generate a random 32-character recovery token
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))

# ... (other imports and code)
# ... (previous imports and code)


# Define a route for the login page, supporting both GET and POST requests

# Define a function to handle login requests
@app.route('/login', methods=['GET', 'POST'])
def login():
    captcha = ''
    captcha_image_io = None
    error_message = ""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not verify_recaptcha(recaptcha_response):
            flash('reCAPTCHA verification failed. Please try again.', category='error')
            return redirect(url_for('login'))

        else:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                session['username'] = user[1]
                session['is_admin'] = user[3] == 'admin'
                return redirect(url_for('home'))  # Redirect to the home page on successful login
            else:
                error_message = "Invalid username, password, or captcha."

    if captcha_image_io is None:
        captcha = generate_captcha()
        captcha_image_io = generate_captcha_image(captcha)
        session['captcha'] = captcha

    # Check if captcha_image_io is still None and provide a default image if needed
    if captcha_image_io is None:
        captcha_image_io = generate_captcha_image("DefaultCaptcha")  # Provide a default captcha image

    captcha_image_base64 = base64.b64encode(captcha_image_io.getvalue()).decode('utf-8')

    return render_template('login.html', captcha=captcha, captcha_image=captcha_image_base64, error_message=error_message)
    return redirect(url_for('login'))

# ... (other routes and code)

# Define a route for displaying user details with a dynamic user_id parameter
@app.route('/user/<int:user_id>')

# Define a function to handle displaying user details
def user_details(user_id):
    # Connect to the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Execute a SQL query to select user information based on the provided user_id
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()

    # Check if a user with the provided user_id exists in the database
    if user:
        # Check the user's role to determine the type of additional information to retrieve 
        if user[3] == 'student':
            cursor.execute("SELECT * FROM students WHERE username=?", (user[1],))
            additional_info = cursor.fetchone()
        elif user[3] == 'teacher':
            cursor.execute("SELECT * FROM teachers WHERE username=?", (user[1],))
            additional_info = cursor.fetchone()
        else:
            additional_info = None
        
        conn.close() # Close the database connection

        print("User details fetched:", user, additional_info) # Print user details and additional information for debugging purposes

        return render_template('user_details.html', user=user, additional_info=additional_info) # Render the 'user_details.html' template with user and additional_info variables
    else:
        return "User not found" # If no user with the provided user_id was found, return a message indicating so
    return redirect(url_for('login'))


@app.route('/student_profile', methods=['GET', 'POST'])
def student_profile():
    if 'username' in session:
        username = session['username']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM students WHERE username=?", (username,))
        student_profile = cursor.fetchone()

        # Check for pending phone number change requests
        cursor.execute("SELECT new_phone_number_request FROM students WHERE username=?", (username,))
        pending_request = cursor.fetchone()

        # Check if the logged-in user is an admin
        is_admin = session.get('is_admin', False)

        # If there is a pending request and the user is an admin, display it for review
        if pending_request and is_admin:
            pending_phone_number_request = pending_request[0]
            return render_template('students.html', student_profile=student_profile, pending_phone_number_request=pending_phone_number_request)
        
        elif request.method == 'POST':
            # Handle form submission (changing password, etc.)
            new_password = request.form['new_password']
            if new_password:
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
                conn.commit()
                flash('Password changed successfully!', 'success')

            # Get updated phone number from the form
            new_phone_number = request.form.get('new_phone_number')

            # If new_phone_number is provided, update the phone number in the database
            if new_phone_number:
                cursor.execute("UPDATE students SET phone_number=?, new_phone_number_request=NULL WHERE username=?", (new_phone_number, username))
                conn.commit()
                flash('Phone number changed successfully!', 'success')

            # Get updated phone number from the database
            cursor.execute("SELECT phone_number FROM students WHERE username=?", (username,))
            updated_phone_number = cursor.fetchone()[0]
            student_profile_dict = {
                'username': student_profile[1],
                'first_name': student_profile[2],
                'last_name': student_profile[3],
                'student_id': student_profile[4],
                'email': student_profile[5],
                'phone_number': updated_phone_number  # Use the updated phone number here
            }
            return render_template('students.html', student_profile=student_profile_dict)
        else:
            # Get phone number from the database
            cursor.execute("SELECT phone_number FROM students WHERE username=?", (username,))
            phone_number = cursor.fetchone()[0]
            student_profile_dict = {
                'username': student_profile[1],
                'first_name': student_profile[2],
                'last_name': student_profile[3],
                'student_id': student_profile[4],
                'email': student_profile[5],
                'phone_number': phone_number  # Use the phone number from the database here
            }
            return render_template('students.html', student_profile=student_profile_dict)

        conn.close()

    return "User not logged in"
    return redirect(url_for('login'))




@app.route('/submit_phone_number_request', methods=['POST'])
def submit_phone_number_request():
    if 'username' in session and request.method == 'POST':
        username = session['username']
        new_phone_number = request.form['new_phone_number']

        # Connect to the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Update the new_phone_number_request column for the specific student
        cursor.execute("UPDATE students SET new_phone_number_request=? WHERE username=?", (new_phone_number, username))
        
        # Update the phone_number column with the new phone number as well
        cursor.execute("UPDATE students SET phone_number=? WHERE username=?", (new_phone_number, username))

        # Commit the changes and close the connection
        conn.commit()
        conn.close()

        flash('Phone number change request submitted successfully!', 'success')
        return redirect(url_for('student_profile'))

    # Handle other cases (e.g., user not logged in or using wrong HTTP method)
    return redirect(url_for('login'))



@app.route('/handle_phone_number_request', methods=['POST'])
def handle_phone_number_request():
    if 'username' in session and session['is_admin'] and request.method == 'POST':
        username = request.form['username']
        new_phone_number = request.form['new_phone_number']
        action = request.form['action']  # 'approve' or 'reject'

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        if action == 'approve':
            # Update the phone_number column with the new phone number
            cursor.execute("UPDATE students SET phone_number=?, new_phone_number_request=NULL WHERE username=?", (new_phone_number, username))
            flash('Phone number change request approved successfully!', 'success')
        elif action == 'reject':
            # Reject the request by clearing the new_phone_number_request column
            cursor.execute("UPDATE students SET new_phone_number_request=NULL WHERE username=?", (username,))
            flash('Phone number change request rejected!', 'warning')

        conn.commit()
        conn.close()

        return redirect(url_for('student_profile'))

    return redirect(url_for('login'))

# Define a route for accessing the home page
@app.route('/home')

# Define a function to handle displaying the home page
def home():
    # Check if the 'username' is stored in the session (indicating a logged-in user)
    if 'username' in session:
        is_admin = session.get('is_admin', False) # Check if the user is an administrator by checking the 'is_admin' flag in the session

        # Create dummy user data (in this case, a list of courses)
        user_data = {
            'courses': ['Maths', 'Science', 'Arts']
        }

        # Render the 'home.html' template with the username, admin status, and user data
        return render_template('home.html', username=session['username'], is_admin=is_admin, user_data=user_data) 
    return redirect(url_for('login')) # If no user is logged in, redirect to the login page


# Define a route for accessing the admin page, supporting both GET and POST requests

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check if the 'username' is stored in the session and if the user is an administrator 
    if 'username' in session and session['is_admin']:
        if request.method == 'POST':
            action = request.form.get('action', '')

            if action == 'add_user':
                # Retrieve new username, new password, and role from the submitted form
                new_username = request.form['new_username']
                new_password = request.form['new_password']
                role = request.form['role']
                first_name = request.form['first_name']
                last_name = request.form['last_name']
                email = request.form['email']
                additional_fields = None

                # Check if the role is 'student' or 'teacher' and set additional fields accordingly
                if role == 'student':
                    student_id = request.form['student_id']
                    additional_fields = (student_id,)
                elif role == 'teacher':
                    employee_id = request.form['employee_id']
                    additional_fields = (employee_id,)

                # Hash the new password using bcrypt
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                # Connect to the database using a context manager
                with sqlite3.connect(DATABASE) as conn:
                    cursor = conn.cursor()

                    # Execute an SQL query to insert a new user with the provided information
                    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                   (new_username, hashed_password, role))

                    # If the role is 'student' or 'teacher', insert additional information into the corresponding table
                    if additional_fields:
                        cursor.execute(f"INSERT INTO {role}s (username, first_name, last_name, {'student_id' if role == 'student' else 'employee_id'}, email) VALUES (?, ?, ?, ?, ?)",
                                       (new_username, first_name, last_name, *additional_fields, email))

                    conn.commit()  # Commit the changes to the database

                flash('User added successfully', 'success')  # Display a success message
                return redirect(url_for('admin'))  # Redirect back to the admin page

            elif action == 'add_course':
                # Retrieve course information from the form
                course_code = request.form['course_code']
                course_name = request.form['course_name']

                # Perform database insertion here
                with sqlite3.connect(DATABASE) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO courses (course_code, course_name) VALUES (?, ?)", (course_code, course_name))
                    conn.commit()

                flash('Course added successfully', 'success')  # Display a success message
                return redirect(url_for('admin'))  # Redirect back to the admin page

        # Fetch the list of teachers and students from the database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, first_name, last_name FROM teachers")
            teachers = cursor.fetchall()
            print("Teachers:", teachers)

            cursor.execute("SELECT id, first_name, last_name FROM students")
            students = cursor.fetchall()
            print("Students",students)

        return render_template('admin.html', teachers=teachers, students=students)  # Render the 'admin.html' template with the list of teachers and students

    return redirect(url_for('login'))  # If the user is not logged in or is not an administrator, redirect to the login page




# Route for assigning students to teachers
@app.route('/assign_students', methods=['GET', 'POST'])
def assign_students():
    if 'is_admin' in session and session['is_admin']:
        if request.method == 'POST':
            teacher_id = request.form['teacher_id']
            student_ids = request.form.getlist('student_ids')

            # Validate that the teacher and students exist in the database
            # You can perform database queries here to check existence

            # Insert records into the assignment table
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            for student_id in student_ids:
                cursor.execute("INSERT INTO teacher_student_assignment (teacher_id, student_id) VALUES (?, ?)", (teacher_id, student_id))

            conn.commit()
            conn.close()

            flash('Students assigned successfully', 'success')
            return redirect(url_for('assign_students'))

        # Fetch a list of teachers and students from the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, name FROM teachers")
        teachers = cursor.fetchall()

        cursor.execute("SELECT id, name FROM students")
        students = cursor.fetchall()

        conn.close()

        return render_template('assign_students.html', teachers=teachers, students=students)

    return "Unauthorized access"
    return redirect(url_for('login'))


# Define a route for logging out
@app.route('/logout')

# Define a function to handle logging out
def logout():
    session.clear() # Clear the session data, effectively logging the user out
    return redirect(url_for('login')) # Redirect the user to the login page after logging out


# Check if this script is being run directly (not imported)
if __name__ == '__main__':
    init_db() # Initialize the database (create necessary tables if they don't exist)
    app.run(debug=True, port=5003) # Run the Flask application in debug mode on port 5003
    #app.run(debug=True, host='0.0.0.0', port=5003)