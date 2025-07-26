import eventlet
eventlet.monkey_patch()

import os
import uuid
import smtplib
import random
from email.message import EmailMessage
from datetime import datetime
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import DictCursor

# --- Flask App Initialization ---
app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')
# In production, this secret key should be loaded from environment variables
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-safe-secret-key')


# --- Database Configuration ---
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        # Using DictCursor globally for consistent, dictionary-like row access
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        return conn
    except psycopg2.Error as e:
        # Log the detailed error for debugging purposes
        print(f"DATABASE CONNECTION ERROR: {e}")
        # Flash a user-friendly message
        flash("Database connection error. Please try again later or contact support.", "danger")
        return None

# --- File Upload Configuration ---
# Folder for event submissions (PDFs, PPTs)
UPLOAD_SUBMISSION_FOLDER = 'uploads'
app.config['UPLOAD_SUBMISSION_FOLDER'] = UPLOAD_SUBMISSION_FOLDER
ALLOWED_SUBMISSION_EXTENSIONS = {'pdf', 'ppt', 'pptx'}

# Folder for event images (PNGs, JPGs) - stored in static for web access
UPLOAD_IMAGE_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_IMAGE_FOLDER'] = UPLOAD_IMAGE_FOLDER
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Folder for brainstorm room file uploads
BRAINSTORM_FOLDER = 'brainstorm_uploads'

# Ensure all upload directories exist
os.makedirs(UPLOAD_SUBMISSION_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_IMAGE_FOLDER, exist_ok=True)
os.makedirs(BRAINSTORM_FOLDER, exist_ok=True)

# In-memory storage for brainstorm room files.
# NOTE: This data is temporary and will be lost on server restart.
# For persistence, file metadata should be stored in the database.
shared_files = {}

# --- Helper Functions ---

def allowed_file(filename, allowed_extensions):
    """Checks if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def get_user_by_id(user_id):
    """Fetches a user's full data by their user_id from the 'users' table."""
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            # SECURITY: Using %s placeholder to prevent SQL injection
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            user_data = cur.fetchone()
            # DictCursor returns a dict-like object, which is perfect
            return user_data
    except psycopg2.Error as e:
        print(f"Database error in get_user_by_id: {e}")
        return None
    finally:
        if conn:
            conn.close()

def send_otp(receiver_email, otp):
    """Sends an OTP to the specified email address."""
    EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("[CONFIG ERROR] Email credentials (EMAIL_USER, EMAIL_PASS) not set in environment variables.")
        flash("Email service is not configured. Please contact an administrator.", "danger")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'OTP Verification - College Club'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your One-Time Password (OTP) is: {otp}\n\nThis OTP is valid for 10 minutes.')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[SUCCESS] OTP sent to {receiver_email}")
        flash("An OTP has been sent to your email address.", "info")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"[AUTH ERROR] SMTP authentication failed. Check credentials or Gmail App Password settings. Error: {e}")
        flash("Failed to send OTP due to a server authentication error.", "danger")
    except Exception as e:
        print(f"[GENERAL ERROR] Failed to send OTP to {receiver_email}. Error: {e}")
        flash("An unexpected error occurred while sending the OTP. Please try again.", "danger")
    return False


# --- Main Routes (Login, Register, Home, Logout) ---

@app.route('/')
def home():
    """Renders the home page with a list of all events."""
    conn = get_db_connection()
    events = []
    if conn:
        try:
            with conn.cursor() as cur:
                # Fetch all events, ordering by the most recent date
                cur.execute("SELECT id, title, short_description, date, image_path FROM events ORDER BY date DESC")
                events = cur.fetchall()
        except psycopg2.Error as e:
            print(f"HOME PAGE EVENTS ERROR: {e}")
            flash(f"Could not load events. Please try again.", "danger")
        finally:
            conn.close()
    return render_template('home.html', events=events)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for all roles (admin, student, mentor)."""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if not conn:
            return render_template('login.html')

        try:
            with conn.cursor() as cur:
                # Check admin table
                cur.execute("SELECT username, password FROM admin WHERE username = %s", (user_id,))
                admin = cur.fetchone()
                if admin and check_password_hash(admin['password'], password):
                    session.update(user_id=admin['username'], name="Admin", role='admin')
                    flash("Admin login successful!", "success")
                    return redirect(url_for('dashboard'))

                # Check users table (students)
                cur.execute("SELECT user_id, name, role, password FROM users WHERE user_id = %s", (user_id,))
                user = cur.fetchone()
                if user and check_password_hash(user['password'], password):
                    session.update(user_id=user['user_id'], name=user['name'], role=user['role'])
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))

                # Check mentors table
                cur.execute("SELECT user_id, name, password FROM mentors WHERE user_id = %s", (user_id,))
                mentor = cur.fetchone()
                if mentor and check_password_hash(mentor['password'], password):
                    session.update(user_id=mentor['user_id'], name=mentor['name'], role='mentor')
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))

                flash("Invalid User ID or Password.", "danger")
        except psycopg2.Error as e:
            print(f"LOGIN ERROR: {e}")
            flash("A database error occurred during login.", "danger")
        finally:
            if conn:
                conn.close()

    return render_template('login.html')

@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    """Handles step 1 of student registration (info collection and OTP)."""
    if request.method == 'POST':
        # Temporarily store form data in session to pass to the next step
        session['registration_data'] = {
            'name': request.form['name'],
            'college': request.form['college'],
            'roll_no': request.form['roll_no'],
            'email': request.form['email']
        }
        
        # OTP is only required for colleges other than "Marwadi"
        if "marwadi" not in session['registration_data']['college'].lower():
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            if send_otp(session['registration_data']['email'], otp):
                # Redirect to step 2 where user will enter OTP and more details
                return redirect(url_for('register_details'))
            else:
                # If OTP sending fails, stay on the page and show error
                return render_template('register_step1.html')
        else:
            # Skip OTP for Marwadi college students
            return redirect(url_for('register_details'))
            
    return render_template('register_step1.html')

@app.route('/register_details', methods=['GET', 'POST'])
def register_details():
    """Handles step 2 of student registration (details, password, and DB insertion)."""
    reg_data = session.get('registration_data')
    if not reg_data:
        flash("Registration session expired. Please start over.", "warning")
        return redirect(url_for('register_student'))
    
    # Check if OTP is needed and submitted
    needs_otp = "marwadi" not in reg_data['college'].lower()

    if request.method == 'POST':
        if needs_otp:
            submitted_otp = request.form.get('otp')
            if not submitted_otp or submitted_otp != session.get('otp'):
                flash("Invalid OTP. Please try again.", "danger")
                return render_template('register_details.html', needs_otp=needs_otp)

        # OTP is verified or not needed, proceed to save user
        if request.form['password'] != request.form['confirm_password']:
            flash("Passwords do not match!", "danger")
            return render_template('register_details.html', needs_otp=needs_otp)

        hashed_password = generate_password_hash(request.form['password'])
        user_id = str(uuid.uuid4())[:8]

        conn = get_db_connection()
        if not conn:
            return render_template('register_details.html', needs_otp=needs_otp)

        try:
            with conn.cursor() as cur:
                # SECURITY: Parameterized query
                cur.execute(
                    """
                    INSERT INTO users (user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'student', %s, %s, %s, %s)
                    """,
                    (
                        user_id, reg_data['name'], reg_data['college'], reg_data['roll_no'], reg_data['email'],
                        request.form['address'], request.form['contact'], request.form['year'],
                        request.form['branch'], request.form['department'], hashed_password
                    )
                )
                conn.commit()
            
            # Clear temporary session data
            session.pop('registration_data', None)
            session.pop('otp', None)

            # Automatically log the new user in
            session.update(user_id=user_id, name=reg_data['name'], role='student')
            flash(f"Registration complete! Your User ID is: {user_id}", "success")
            return redirect(url_for('dashboard'))

        except psycopg2.Error as e:
            print(f"STUDENT REGISTRATION ERROR: {e}")
            conn.rollback()
            flash("Registration failed due to a database error. It's possible the email or roll number is already in use.", "danger")
        finally:
            if conn:
                conn.close()

    return render_template('register_details.html', needs_otp=needs_otp)

@app.route('/register_mentor', methods=['GET', 'POST'])
def register_mentor():
    """Handles mentor registration."""
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            flash("Passwords do not match!", "danger")
            return render_template('register_mentor.html')

        hashed_password = generate_password_hash(request.form['password'])
        user_id = str(uuid.uuid4())[:8]

        conn = get_db_connection()
        if not conn:
            return render_template('register_mentor.html')

        try:
            with conn.cursor() as cur:
                # SECURITY: Parameterized query
                cur.execute(
                    """
                    INSERT INTO mentors (user_id, name, college, email, expertise, skills, password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, request.form['name'], request.form['college'], request.form['email'], 
                     request.form['expertise'], request.form['skills'], hashed_password)
                )
                conn.commit()

            session.update(user_id=user_id, name=request.form['name'], role='mentor')
            flash(f"Mentor registration complete! Your User ID is: {user_id}", "success")
            return redirect(url_for('dashboard'))

        except psycopg2.Error as e:
            print(f"MENTOR REGISTRATION ERROR: {e}")
            conn.rollback()
            flash("Registration failed due to a database error.", "danger")
        finally:
            if conn:
                conn.close()
    
    return render_template('register_mentor.html')

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))


# --- Dashboard and Profile Routes ---

@app.route('/dashboard')
def dashboard():
    """Redirects user to the appropriate dashboard based on their role."""
    if 'role' in session:
        role = session['role']
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'mentor':
            return redirect(url_for('mentor_dashboard'))
    return redirect(url_for('login'))


@app.route('/student_dashboard')
def student_dashboard():
    """Displays the student dashboard with events and results."""
    if session.get('role') != 'student':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    student_data, events, results = None, [], {}
    if conn:
        try:
            with conn.cursor() as cur:
                # Fetch student's personal info
                cur.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
                student_data = cur.fetchone()
                
                # Fetch all available events
                cur.execute("SELECT * FROM events ORDER BY date DESC")
                events = cur.fetchall()
                
                # Fetch all event results
                cur.execute("SELECT event_title, position, winner_name, winner_email FROM event_results ORDER BY event_title, position")
                raw_results = cur.fetchall()
                for res in raw_results:
                    results.setdefault(res['event_title'], []).append(res)
        except psycopg2.Error as e:
            print(f"STUDENT DASHBOARD ERROR: {e}")
            flash("Failed to load dashboard data.", "danger")
        finally:
            if conn:
                conn.close()
            
    return render_template('student_dashboard.html', student=student_data, events=events, results=results, role='student')


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Displays admin dashboard and handles event creation."""
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    event_stats = []
    if not conn:
        return render_template('admin_dashboard.html', event_stats=event_stats)

    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                # Process new event creation
                image_file = request.files.get('event_image')
                image_path_for_db = None
                if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                    filename = secure_filename(image_file.filename)
                    # Save image to the static/uploads directory
                    image_file.save(os.path.join(app.config['UPLOAD_IMAGE_FOLDER'], filename))
                    # Store relative path for use in templates
                    image_path_for_db = os.path.join('uploads', filename)

                # Insert event and get its new ID
                cur.execute(
                    "INSERT INTO events (title, short_description, description, date, image_path) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (request.form['title'], request.form['short_description'], request.form['description'], request.form['date'], image_path_for_db)
                )
                event_id = cur.fetchone()['id']
                
                # Insert associated stages
                for title, deadline in zip(request.form.getlist('stage_title[]'), request.form.getlist('deadline[]')):
                    if title and deadline:
                        cur.execute("INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)", (event_id, title, deadline))
                
                conn.commit()
                flash("New event created successfully!", "success")
                return redirect(url_for('admin_dashboard'))

            # Fetch stats for all existing events
            cur.execute("SELECT * FROM events ORDER BY date DESC")
            events = cur.fetchall()
            for event in events:
                cur.execute("SELECT COUNT(*) FROM event_registrations WHERE event_id = %s", (event['id'],))
                registered_count = cur.fetchone()['count']
                cur.execute("SELECT COUNT(DISTINCT user_id) FROM submissions WHERE event_id = %s", (event['id'],))
                submitted_count = cur.fetchone()['count']
                event_stats.append({'event': event, 'registered': registered_count, 'submitted': submitted_count})
        
        return render_template('admin_dashboard.html', event_stats=event_stats)

    except Exception as e:
        print(f"!!! UNHANDLED ERROR IN ADMIN DASHBOARD: {e} !!!")
        if conn:
            conn.rollback()
        flash("An unexpected error occurred while loading the admin dashboard. Please contact support.", "danger")
        return redirect(url_for('home'))
    finally:
        if conn:
            conn.close()


@app.route('/mentor_dashboard')
def mentor_dashboard():
    """Displays the mentor dashboard."""
    if session.get('role') != 'mentor':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    events, rooms, results = [], [], defaultdict(list)
    if conn:
        try:
            with conn.cursor() as cur:
                # Fetch all events with stages
                cur.execute("SELECT * FROM events ORDER BY date DESC")
                all_events = cur.fetchall()
                for event in all_events:
                    cur.execute("SELECT * FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event['id'],))
                    event_stages = cur.fetchall()
                    events.append({'details': event, 'stages': event_stages})
                
                # Fetch all brainstorm rooms
                cur.execute("SELECT room_id, title, created_by, created_at FROM brainstorm_rooms ORDER BY created_at DESC")
                rooms = cur.fetchall()
                
                # Fetch all event results
                cur.execute("SELECT * FROM event_results ORDER BY event_title, position")
                raw_results = cur.fetchall()
                for res in raw_results:
                    results[res['event_title']].append(res)
        except psycopg2.Error as e:
            print(f"MENTOR DASHBOARD ERROR: {e}")
            flash("Failed to load mentor dashboard data.", "danger")
        finally:
            if conn:
                conn.close()

    return render_template('mentor_dashboard.html', events=events, brainstorm_rooms=rooms, results=results, role='mentor')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Displays and handles updates for the user's profile."""
    if 'user_id' not in session:
        flash("Please log in to view your profile.", "info")
        return redirect(url_for('login'))
        
    role = session['role']
    
    if request.method == 'POST':
        conn = get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    # SECURITY: Use separate, safe queries for each role
                    if role == 'student':
                        cur.execute(
                            "UPDATE users SET contact = %s, address = %s, year = %s, branch = %s, department = %s WHERE user_id = %s",
                            (request.form['contact'], request.form['address'], request.form['year'], request.form['branch'], request.form['department'], session['user_id'])
                        )
                    elif role == 'mentor':
                         cur.execute(
                            "UPDATE mentors SET college = %s, expertise = %s, skills = %s WHERE user_id = %s",
                            (request.form['college'], request.form['expertise'], request.form['skills'], session['user_id'])
                        )
                    conn.commit()
                    flash("Profile updated successfully!", "success")
            except psycopg2.Error as e:
                print(f"PROFILE UPDATE ERROR: {e}")
                conn.rollback()
                flash("Failed to update profile due to a database error.", "danger")
            finally:
                if conn:
                    conn.close()
        return redirect(url_for('profile'))

    # Fetch current user data for display
    user_data = None
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                # SECURITY: Use separate, safe queries for each role
                if role == 'student':
                    cur.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
                elif role == 'mentor':
                    cur.execute("SELECT * FROM mentors WHERE user_id = %s", (session['user_id'],))
                user_data = cur.fetchone()
        except psycopg2.Error as e:
            print(f"PROFILE FETCH ERROR: {e}")
        finally:
            if conn:
                conn.close()

    if not user_data:
        flash("Could not retrieve user profile. Please log in again.", "danger")
        return redirect(url_for('login'))
        
    return render_template('profile.html', user_data=user_data, role=role)


@app.route('/change_password', methods=['POST'])
def change_password():
    """Handles password change requests for the logged-in user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    if new_password != confirm_new_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))
        
    if len(new_password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for('profile'))

    role = session['role']
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('profile'))
        
    try:
        with conn.cursor() as cur:
            user = None
            # SECURITY: Use separate, safe queries for each role
            if role == 'admin':
                cur.execute("SELECT password FROM admin WHERE username = %s", (session['user_id'],))
            elif role == 'student':
                cur.execute("SELECT password FROM users WHERE user_id = %s", (session['user_id'],))
            elif role == 'mentor':
                cur.execute("SELECT password FROM mentors WHERE user_id = %s", (session['user_id'],))
            user = cur.fetchone()

            if not user or not check_password_hash(user['password'], current_password):
                flash("Current password incorrect.", "danger")
                return redirect(url_for('profile'))

            hashed_new_password = generate_password_hash(new_password)
            
            # SECURITY: Use separate, safe update queries
            if role == 'admin':
                cur.execute("UPDATE admin SET password = %s WHERE username = %s", (hashed_new_password, session['user_id']))
            elif role == 'student':
                cur.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_new_password, session['user_id']))
            elif role == 'mentor':
                cur.execute("UPDATE mentors SET password = %s WHERE user_id = %s", (hashed_new_password, session['user_id']))

            conn.commit()
            flash("Password changed successfully!", "success")
    except psycopg2.Error as e:
        print(f"CHANGE PASSWORD ERROR: {e}")
        conn.rollback()
        flash("Failed to change password due to a database error.", "danger")
    finally:
        if conn:
            conn.close()
        
    return redirect(url_for('profile'))


# --- Event and Submission Routes ---

@app.route('/event/<int:event_id>', methods=['GET', 'POST'])
def event_detail(event_id):
    """Displays details for a single event and handles registration."""
    if 'user_id' not in session:
        flash("Please log in to view event details.", "info")
        return redirect(url_for('login'))

    conn = get_db_connection()
    event, is_registered = None, False
    if conn:
        try:
            with conn.cursor() as cur:
                # Fetch event details
                cur.execute("SELECT * FROM events WHERE id = %s", (event_id,))
                event = cur.fetchone()

                if event:
                    # Check if the current user is already registered
                    cur.execute("SELECT 1 FROM event_registrations WHERE user_id = %s AND event_id = %s", (session['user_id'], event_id))
                    is_registered = cur.fetchone() is not None

                if request.method == 'POST' and session['role'] == 'student' and not is_registered:
                    # Handle event registration for students
                    cur.execute("INSERT INTO event_registrations (user_id, event_id) VALUES (%s, %s)", (session['user_id'], event_id))
                    conn.commit()
                    flash("Successfully registered for the event!", "success")
                    return redirect(url_for('student_registered_events'))
        except psycopg2.Error as e:
            print(f"EVENT DETAIL ERROR: {e}")
            conn.rollback()
            flash("A database error occurred.", "danger")
        finally:
            if conn:
                conn.close()
            
    if not event:
        abort(404)
        
    return render_template('event_detail.html', event=event, registered=is_registered)


@app.route('/registered_events')
def student_registered_events():
    """Shows a student all events they are registered for, including stage status."""
    if session.get('role') != 'student':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    events_data = []
    if conn:
        try:
            with conn.cursor() as cur:
                # Get events the student is registered for
                cur.execute(
                    """
                    SELECT e.* FROM events e
                    JOIN event_registrations r ON e.id = r.event_id
                    WHERE r.user_id = %s ORDER BY e.date DESC
                    """, (session['user_id'],)
                )
                events = cur.fetchall()
                
                for event in events:
                    # Get stages for each event
                    cur.execute("SELECT * FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event['id'],))
                    stages = cur.fetchall()
                    
                    # For each stage, check if there is a submission
                    for stage in stages:
                        cur.execute(
                            "SELECT * FROM submissions WHERE user_id = %s AND stage_id = %s",
                            (session['user_id'], stage['id'])
                        )
                        submission = cur.fetchone()
                        stage['submission'] = submission # Attach submission info to stage dict
                    
                    events_data.append({'details': event, 'stages': stages})
        except psycopg2.Error as e:
            print(f"REGISTERED EVENTS ERROR: {e}")
            flash("Failed to load your registered events.", "danger")
        finally:
            if conn:
                conn.close()
            
    return render_template('registered_events.html', events_data=events_data)


@app.route('/submit/<int:event_id>/<int:stage_id>', methods=['GET', 'POST'])
def submit_stage(event_id, stage_id):
    """Handles student submission for a specific event stage."""
    if session.get('role') != 'student':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    stage = None
    if not conn:
        return redirect(url_for('student_registered_events'))

    try:
        with conn.cursor() as cur:
            # Check if user has already submitted for this stage
            cur.execute("SELECT 1 FROM submissions WHERE user_id = %s AND stage_id = %s", (session['user_id'], stage_id))
            if cur.fetchone():
                flash("You have already submitted for this stage. Resubmission is not allowed.", "warning")
                return redirect(url_for('student_registered_events'))
                
            # Get stage info to check deadline
            cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
            stage = cur.fetchone()
            if not stage or datetime.now().date() > stage['deadline']:
                flash("Submission deadline has passed or the stage is invalid.", "danger")
                return redirect(url_for('student_registered_events'))

            if request.method == 'POST':
                file = request.files.get('submission_file')
                file_path_for_db = None
                if file and allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                    filename = secure_filename(f"{session['user_id']}_{stage_id}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_SUBMISSION_FOLDER'], filename))
                    file_path_for_db = filename

                # Insert submission record
                cur.execute(
                    """
                    INSERT INTO submissions (user_id, event_id, stage_id, submission_text, submission_file, submitted_on)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (session['user_id'], event_id, stage_id, request.form.get('submission_text'), file_path_for_db, datetime.now())
                )
                conn.commit()
                flash("Submission successful!", "success")
                return redirect(url_for('student_registered_events'))
    except psycopg2.Error as e:
        print(f"SUBMISSION ERROR: {e}")
        conn.rollback()
        flash("A database error occurred during submission.", "danger")
    finally:
        if conn:
            conn.close()

    return render_template('submit_stage.html', stage=stage, event_id=event_id, stage_id=stage_id)


# --- Admin-Specific Routes (Progress, Users, Winners) ---

@app.route('/view_progress/<int:event_id>')
def view_progress(event_id):
    """Displays submission progress for all participants in an event."""
    if session.get('role') not in ['admin', 'mentor']:
        return redirect(url_for('login'))

    conn = get_db_connection()
    progress_data, stages, event_title = [], [], "Unknown Event"
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT title FROM events WHERE id = %s", (event_id,))
                event = cur.fetchone()
                if not event: abort(404)
                event_title = event['title']
                
                cur.execute("SELECT id, stage_title FROM event_stages WHERE event_id = %s", (event_id,))
                stages = cur.fetchall()
                stage_map = {s['id']: s['stage_title'] for s in stages}

                cur.execute(
                    """
                    SELECT u.user_id, u.name, u.email FROM users u
                    JOIN event_registrations r ON u.user_id = r.user_id
                    WHERE r.event_id = %s
                    """, (event_id,)
                )
                participants = cur.fetchall()

                for p in participants:
                    p['stage_status'] = {s['stage_title']: None for s in stages}
                    cur.execute("SELECT stage_id, submission_file FROM submissions WHERE user_id = %s AND event_id = %s", (p['user_id'], event_id))
                    submissions = cur.fetchall()
                    for sub in submissions:
                        stage_title = stage_map.get(sub['stage_id'])
                        if stage_title:
                            p['stage_status'][stage_title] = sub['submission_file']
                    progress_data.append(p)
        except psycopg2.Error as e:
            print(f"VIEW PROGRESS ERROR: {e}")
            flash("Failed to load progress data.", "danger")
        finally:
            if conn:
                conn.close()
            
    return render_template('view_progress.html', progress=progress_data, stages=[s['stage_title'] for s in stages], event_title=event_title)


@app.route('/view_all_users')
def view_all_users():
    """Displays a list of all registered users and mentors."""
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    users = []
    if conn:
        try:
            with conn.cursor() as cur:
                # FIX: Added NULL placeholders for columns missing in mentors table to allow UNION
                cur.execute("""
                    SELECT user_id, name, 'student' as role, email, contact, address, college, roll_no, branch
                    FROM users
                    UNION ALL
                    SELECT user_id, name, 'mentor' as role, email, NULL as contact, NULL as address, college, NULL as roll_no, NULL as branch
                    FROM mentors
                """)
                users = cur.fetchall()
        except psycopg2.Error as e:
            print(f"VIEW ALL USERS ERROR: {e}")
            flash("Failed to fetch user list.", "danger")
        finally:
            if conn:
                conn.close()

    return render_template('all_users.html', users=users)

@app.route('/announce_winner', methods=['POST'])
def announce_winner():
    """Handles form submission for announcing event winners."""
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                event_title = request.form['event_title']
                for i in range(1, 4):
                    position = request.form.get(f'position{i}')
                    name = request.form.get(f'name{i}')
                    email = request.form.get(f'email{i}')
                    if position and name and email:
                        cur.execute(
                            "INSERT INTO event_results (event_title, position, winner_name, winner_email) VALUES (%s, %s, %s, %s)",
                            (event_title, position, name, email)
                        )
                conn.commit()
                flash("Winners announced successfully!", "success")
        except psycopg2.Error as e:
            print(f"ANNOUNCE WINNER ERROR: {e}")
            conn.rollback()
            flash("A database error occurred while announcing winners.", "danger")
        finally:
            if conn:
                conn.close()
    
    return redirect(url_for('admin_dashboard'))


# --- Brainstorm Room (Chat) Routes and SocketIO Events ---

@app.route('/brainstorm', methods=['GET', 'POST'])
def brainstorm():
    """Lists available brainstorm rooms and handles new room creation."""
    if session.get('role') not in ['student', 'mentor']:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return render_template('brainstorm.html', rooms=[])
        
    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                room_id = str(uuid.uuid4())[:8]
                cur.execute(
                    "INSERT INTO brainstorm_rooms (room_id, title, created_by, created_at) VALUES (%s, %s, %s, %s)",
                    (room_id, request.form['room_title'], session['user_id'], datetime.now())
                )
                conn.commit()
                flash("Room created successfully!", "success")
                return redirect(url_for('join_brainstorm_room', room_id=room_id))
            
            # GET request: fetch and display all rooms
            cur.execute("SELECT room_id, title, created_at FROM brainstorm_rooms ORDER BY created_at DESC")
            rooms_data = cur.fetchall()
    except psycopg2.Error as e:
        print(f"BRAINSTORM PAGE ERROR: {e}")
        conn.rollback()
        flash("A database error occurred.", "danger")
        rooms_data = []
    finally:
        if conn:
            conn.close()

    return render_template('brainstorm.html', rooms=rooms_data)


@app.route('/brainstorm/room/<room_id>')
def join_brainstorm_room(room_id):
    """Renders the main view for a specific brainstorm room."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    room_details, chat_history, creator_name = None, [], "Unknown"
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM brainstorm_rooms WHERE room_id = %s", (room_id,))
                room_details = cur.fetchone()
                if not room_details: abort(404)
                
                # Fetch chat history for the room
                cur.execute("SELECT username, message, timestamp FROM brainstorm_chats WHERE room_id = %s ORDER BY timestamp ASC", (room_id,))
                chat_history = cur.fetchall()
                
                # Find the name of the room creator
                cur.execute("SELECT name FROM users WHERE user_id = %s", (room_details['created_by'],))
                creator = cur.fetchone()
                if not creator:
                    cur.execute("SELECT name FROM mentors WHERE user_id = %s", (room_details['created_by'],))
                    creator = cur.fetchone()
                creator_name = creator['name'] if creator else "Unknown"
        except psycopg2.Error as e:
            print(f"BRAINSTORM ROOM ERROR: {e}")
            flash("Failed to load room data.", "danger")
        finally:
            if conn:
                conn.close()
            
    # Files are fetched via a separate JS call to /brainstorm/files/<room>
    return render_template(
        'brainstorm_room.html',
        room_id=room_id,
        room_details=room_details,
        user_name=session['name'],
        chat_history=chat_history,
        creator_name=creator_name
    )

@app.route('/brainstorm/upload/<room_id>', methods=['POST'])
def upload_file_brainstorm(room_id):
    """Handles file uploads for a brainstorm room (via AJAX)."""
    if 'file' not in request.files:
        return jsonify(status='error', message='No file part'), 400
    file = request.files['file']
    user_who_uploaded = request.form.get('user', 'Anonymous')
    
    if file.filename == '':
        return jsonify(status='error', message='No selected file'), 400
        
    if file:
        filename = secure_filename(file.filename)
        save_path = os.path.join(BRAINSTORM_FOLDER, filename)
        file.save(save_path)
        
        file_url = url_for('download_brainstorm_file', filename=filename)
        timestamp = datetime.now().isoformat()
        
        # NOTE: Persisting file info to the temporary in-memory dict
        file_metadata = {'filename': filename, 'url': file_url, 'user': user_who_uploaded, 'timestamp': timestamp}
        shared_files.setdefault(room_id, []).append(file_metadata)
        
        # Notify other users in the room via SocketIO
        socketio.emit('file_shared', file_metadata, to=room_id)
        
        return jsonify(status='success', **file_metadata)
    
    return jsonify(status='error', message='File upload failed'), 500


@app.route('/brainstorm/files/<room_id>')
def get_shared_files(room_id):
    """Returns a JSON list of files for a room from the in-memory store."""
    return jsonify(shared_files.get(room_id, []))


@socketio.on('join')
def handle_join(data):
    """Handles a user joining a SocketIO room."""
    room = data.get('room')
    user = data.get('user', 'Anonymous')
    if room and user:
        join_room(room)
        # Emit a system message to the room
        emit('message', {'user': 'System', 'msg': f"{user} has joined the room.", 'timestamp': datetime.now().isoformat()}, to=room)


@socketio.on('send_message')
def handle_send_message(data):
    """Receives, saves, and broadcasts a chat message."""
    room, user, msg = data.get('room'), data.get('user'), data.get('msg')
    if not all([room, user, msg]):
        return # Ignore invalid messages
        
    timestamp = datetime.now()
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO brainstorm_chats (room_id, username, message, timestamp) VALUES (%s, %s, %s, %s)", (room, user, msg, timestamp))
                conn.commit()
            # On successful save, broadcast the message to the room
            emit('message', {'user': user, 'msg': msg, 'timestamp': timestamp.isoformat()}, to=room)
        except psycopg2.Error as e:
            print(f"CHAT MESSAGE SAVE ERROR: {e}")
            conn.rollback()
        finally:
            if conn:
                conn.close()

# --- File Download Routes ---

@app.route('/download_brainstorm_file/<path:filename>')
def download_brainstorm_file(filename):
    """Serves files uploaded in brainstorm rooms for download."""
    return send_from_directory(BRAINSTORM_FOLDER, filename, as_attachment=True)


@app.route('/download_submission/<path:filename>')
def download_submission(filename):
    """Serves submitted files for events for download."""
    return send_from_directory(app.config['UPLOAD_SUBMISSION_FOLDER'], filename, as_attachment=True)


# --- Main Execution ---
if __name__ == '__main__':
    socketio.run(app, debug=True)
