import eventlet
eventlet.monkey_patch()

import os
import uuid
import smtplib
import random
from email.message import EmailMessage
from datetime import datetime
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import DictCursor
import cloudinary
import cloudinary.uploader

# --- Flask App Initialization ---
app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')
# IMPORTANT: In production, load this from environment variables for security.
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-safe-secret-key-that-you-must-change')

# --- Cloudinary Configuration ---
# Your Cloudinary credentials will be loaded from environment variables.
# Ensure CLOUD_NAME, API_KEY, and API_SECRET are set in your environment.
cloudinary.config(
  cloud_name=os.getenv('CLOUD_NAME'),
  api_key=os.getenv('API_KEY'),
  api_secret=os.getenv('API_SECRET')
)

# --- Database Configuration ---
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        return conn
    except psycopg2.Error as e:
        print(f"DATABASE CONNECTION ERROR: {e}")
        flash("Database connection error. Please try again later.", "danger")
        return None

# --- Helper Functions ---

ALLOWED_SUBMISSION_EXTENSIONS = {'pdf', 'ppt', 'pptx'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename, allowed_extensions):
    """Checks if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def send_otp(receiver_email, otp):
    """Sends a One-Time Password (OTP) to the specified email address."""
    EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("[CONFIG ERROR] Email credentials (EMAIL_USER, EMAIL_PASS) are not set in environment variables.")
        flash("Email service is not configured. Please contact an administrator.", "danger")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'Your OTP for College Club Registration'
    msg['From'] = f'College Club <{EMAIL_ADDRESS}>'
    msg['To'] = receiver_email
    msg.set_content(f'Your One-Time Password (OTP) is: {otp}\n\nThis OTP is valid for 10 minutes and should not be shared.')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[SUCCESS] OTP sent to {receiver_email}")
        flash("An OTP has been sent to your email. Please check your inbox.", "info")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP to {receiver_email}. Error: {e}")
        flash("An unexpected error occurred while sending the OTP. Please try again.", "danger")
    return False

# --- Core Routes (Home, Auth, Dashboards) ---

@app.route('/')
def home():
    """Renders the home page with a list of all events."""
    conn = get_db_connection()
    events = []
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, title, short_description, date, image_path FROM events ORDER BY date DESC")
                events = cur.fetchall()
        except psycopg2.Error as e:
            print(f"HOME PAGE EVENTS ERROR: {e}")
            flash("Could not load events.", "danger")
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
                # 1. Check admin table
                cur.execute("SELECT username, password FROM admin WHERE username = %s", (user_id,))
                admin = cur.fetchone()
                if admin and check_password_hash(admin['password'], password):
                    session.update(user_id=admin['username'], name="Admin", role='admin')
                    flash("Admin login successful!", "success")
                    return redirect(url_for('dashboard'))
                # 2. Check users (student) table
                cur.execute("SELECT user_id, name, role, password FROM users WHERE user_id = %s", (user_id,))
                user = cur.fetchone()
                if user and check_password_hash(user['password'], password):
                    session.update(user_id=user['user_id'], name=user['name'], role=user['role'])
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))
                # 3. Check mentors table
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
    """Handles step 1 of student registration (info collection and OTP trigger)."""
    if request.method == 'POST':
        # Store form data in session to pass to the next step
        session['registration_data'] = {
            'name': request.form['name'],
            'college': request.form['college'],
            'roll_no': request.form['roll_no'],
            'email': request.form['email']
        }
        # OTP is only required for colleges other than "Marwadi" (case-insensitive)
        if "marwadi" not in session['registration_data']['college'].lower():
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            # If OTP sending is successful, proceed to the details page
            if send_otp(session['registration_data']['email'], otp):
                return redirect(url_for('register_details'))
            else:
                # If OTP sending fails, stay on the page; flash message is handled in send_otp
                return render_template('register_step1.html')
        else:
            # Skip OTP for Marwadi college students
            return redirect(url_for('register_details'))
    return render_template('register_step1.html')

@app.route('/register_details', methods=['GET', 'POST'])
def register_details():
    """Handles step 2 of student registration (OTP verification and final DB insertion)."""
    reg_data = session.get('registration_data')
    if not reg_data:
        flash("Your registration session has expired. Please start over.", "warning")
        return redirect(url_for('register_student'))
    
    needs_otp = "marwadi" not in reg_data['college'].lower()

    if request.method == 'POST':
        # Verify OTP if required
        if needs_otp:
            if request.form.get('otp') != session.get('otp'):
                flash("The OTP you entered is incorrect. Please try again.", "danger")
                return render_template('register_details.html', needs_otp=needs_otp)
        
        # Check if passwords match
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
            
            # Clean up session and log the user in
            session.pop('registration_data', None)
            session.pop('otp', None)
            session.update(user_id=user_id, name=reg_data['name'], role='student')
            flash(f"Registration successful! Your User ID is: {user_id}", "success")
            return redirect(url_for('dashboard'))

        except psycopg2.Error as e:
            print(f"STUDENT REGISTRATION ERROR: {e}")
            conn.rollback()
            flash("Registration failed. The email or roll number might already be in use.", "danger")
        finally:
            if conn:
                conn.close()

    return render_template('register_details.html', needs_otp=needs_otp)
    
@app.route('/dashboard')
def dashboard():
    """Redirects user to the appropriate dashboard based on their role."""
    role = session.get('role')
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role == 'mentor':
        return redirect(url_for('mentor_dashboard'))
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

# --- Admin Routes ---

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Renders the admin dashboard and handles new event creation with Cloudinary uploads."""
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return render_template('admin_dashboard.html', event_stats=[])

    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                image_file = request.files.get('event_image')
                image_url = None
                if image_file and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(image_file, folder="event_images")
                        image_url = upload_result.get('secure_url')
                    except Exception as e:
                        flash(f"Image upload to Cloudinary failed: {e}", "danger")
                
                cur.execute(
                    "INSERT INTO events (title, short_description, description, date, image_path) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (request.form['title'], request.form['short_description'], request.form['description'], request.form['date'], image_url)
                )
                event_id = cur.fetchone()[0]

                for title, deadline in zip(request.form.getlist('stage_title[]'), request.form.getlist('deadline[]')):
                    if title and deadline:
                        cur.execute("INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)", (event_id, title, deadline))
                
                conn.commit()
                flash("New event created successfully!", "success")
                return redirect(url_for('admin_dashboard'))

            # Fetch event stats for display
            event_stats = []
            cur.execute("SELECT * FROM events ORDER BY date DESC")
            events = cur.fetchall()
            for event in events:
                cur.execute("SELECT COUNT(*) AS total FROM event_registrations WHERE event_id = %s", (event['id'],))
                registered = cur.fetchone()['total']
                cur.execute("SELECT COUNT(DISTINCT user_id) AS total FROM submissions WHERE event_id = %s", (event['id'],))
                submitted = cur.fetchone()['total']
                event_stats.append({'event': event, 'registered': registered, 'submitted': submitted})

            return render_template('admin_dashboard.html', event_stats=event_stats)

    except Exception as e:
        print(f"ADMIN DASHBOARD ERROR: {e}")
        if conn: conn.rollback()
        flash("An unexpected error occurred on the admin dashboard.", "danger")
        return redirect(url_for('home'))
    finally:
        if conn: conn.close()
        
# --- All other routes from previous versions are included below ---

@app.route('/mentor_dashboard')
def mentor_dashboard():
    """Renders the mentor dashboard with events, rooms, and results."""
    if 'user' not in session or session.get('role') != 'mentor':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('mentor_dashboard.html', events=[], brainstorm_rooms=[], results={})

    events_for_template = []
    rooms = []
    processed_results = defaultdict(list)

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
            events_raw = cur.fetchall()

            for event_row in events_raw:
                event_id = event_row['id']
                event_data = {
                    'id': event_id,
                    'title': event_row['title'],
                    'description': event_row['description'],
                    'date': event_row['date'],
                    'short_description': event_row['short_description'],
                    'image_path': event_row['image_path'],
                    'stages': []
                }
                cur.execute("SELECT id, stage_title, deadline FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
                stages_for_event = cur.fetchall()
                for stage_row in stages_for_event:
                    event_data['stages'].append({
                        'id': stage_row['id'],
                        'stage_title': stage_row['stage_title'],
                        'deadline': stage_row['deadline']
                    })
                events_for_template.append(event_data)

            cur.execute("SELECT room_id, title, created_by FROM brainstorm_rooms ORDER BY created_at DESC")
            rooms = cur.fetchall()

            cur.execute('''
                SELECT event_title, position, winner_name
                FROM event_results
                ORDER BY event_title,
                         CASE
                             WHEN position LIKE '1%' THEN 1
                             WHEN position LIKE '2%' THEN 2
                             WHEN position LIKE '3%' THEN 3
                             ELSE 4
                         END
            ''')
            raw_results = cur.fetchall()
            for result_row in raw_results:
                event_title = result_row['event_title']
                position = result_row['position']
                winner_name = result_row['winner_name']
                processed_results[event_title].append([winner_name, position, ""])

    except psycopg2.Error as e:
        flash(f"Database error on mentor dashboard: {e}", "danger")
        print(f"MENTOR DASHBOARD ERROR: {e}")
    finally:
        if conn: conn.close()

    return render_template('mentor_dashboard.html',
                           events=events_for_template,
                           brainstorm_rooms=rooms,
                           results=dict(processed_results),
                           role=session.get('role'))
                           
@app.route('/student_dashboard')
def student_dashboard():
    """Renders the student dashboard with personal info, events, and results."""
    if 'user' not in session or session.get('role') != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('student_dashboard.html', student=None, events=[], results={})

    student = None
    events = []
    grouped_results = {}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department FROM users WHERE user_id = %s", (session['user_id'],))
            student = cur.fetchone()

            cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
            events = cur.fetchall()

            cur.execute('''
                SELECT event_title, position, winner_name, winner_email
                FROM event_results
                ORDER BY event_title,
                         CASE 
                             WHEN position LIKE '1%' THEN 1
                             WHEN position LIKE '2%' THEN 2
                             WHEN position LIKE '3%' THEN 3
                             ELSE 4
                         END
            ''')
            raw_results = cur.fetchall()
            for result_row in raw_results:
                event_title = result_row['event_title']
                position = result_row['position']
                name = result_row['winner_name']
                email = result_row['winner_email']
                if event_title not in grouped_results:
                    grouped_results[event_title] = []
                grouped_results[event_title].append((position, name, email))
    except psycopg2.Error as e:
        flash(f"Database error on student dashboard: {e}", "danger")
        print(f"STUDENT DASHBOARD ERROR: {e}")
    finally:
        if conn: conn.close()

    return render_template('student_dashboard.html', student=student, events=events, results=grouped_results, role=session.get('role'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Displays and allows updating of user profile."""
    if 'user_id' not in session:
        flash("Unauthorized access. Please log in.", "danger")
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('dashboard'))

    # Fetch user data for display
    try:
        with conn.cursor() as cur:
            if session['role'] == 'student':
                 cur.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
            elif session['role'] == 'mentor':
                cur.execute("SELECT * FROM mentors WHERE user_id = %s", (session['user_id'],))
            user_data = cur.fetchone()

        if request.method == 'POST':
            # Handle profile update
            with conn.cursor() as cur:
                if session['role'] == 'student':
                    cur.execute(
                        "UPDATE users SET contact=%s, address=%s, year=%s, branch=%s, department=%s WHERE user_id=%s",
                        (request.form['contact'], request.form['address'], request.form['year'], request.form['branch'], request.form['department'], session['user_id'])
                    )
                elif session['role'] == 'mentor':
                    cur.execute(
                        "UPDATE mentors SET college=%s, expertise=%s, skills=%s WHERE user_id=%s",
                        (request.form['college'], request.form['expertise'], request.form['skills'], session['user_id'])
                    )
                conn.commit()
                flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))

    except psycopg2.Error as e:
        flash("A database error occurred.", "danger")
        print(f"PROFILE ERROR: {e}")
        if conn: conn.rollback()
        return redirect(url_for('dashboard'))
    finally:
        if conn: conn.close()

    if not user_data:
        flash("Could not retrieve user profile.", "danger")
        return redirect(url_for('login'))

    return render_template('profile.html', user_data=user_data)
    
@app.route('/submit/<int:event_id>/<int:stage_id>', methods=['GET', 'POST'])
def submit_stage(event_id, stage_id):
    """Handles student submission for a specific event stage, uploading file to Cloudinary."""
    if session.get('role') != 'student':
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        return redirect(url_for('student_registered_events'))

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
            stage = cur.fetchone()
            if not stage or datetime.now().date() > stage['deadline']:
                flash("Submission deadline has passed or the stage is invalid.", "danger")
                return redirect(url_for('student_registered_events'))
            
            cur.execute("SELECT id FROM submissions WHERE user_id = %s AND stage_id = %s", (session['user_id'], stage_id))
            if cur.fetchone():
                flash("You have already submitted for this stage.", "warning")
                return redirect(url_for('student_registered_events'))

            if request.method == 'POST':
                file = request.files.get('submission_file')
                file_url = None
                if file and allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(file, resource_type="auto", folder="submissions")
                        file_url = upload_result.get('secure_url')
                    except Exception as e:
                        flash(f"File upload failed: {e}", "danger")
                        return render_template('submit_stage.html', stage=stage, event_id=event_id, stage_id=stage_id)

                cur.execute(
                    "INSERT INTO submissions (user_id, event_id, stage_id, submission_text, submission_file, submitted_on) VALUES (%s, %s, %s, %s, %s, %s)",
                    (session['user_id'], event_id, stage_id, request.form.get('submission_text'), file_url, datetime.now())
                )
                conn.commit()
                flash("Submission successful!", "success")
                return redirect(url_for('student_registered_events'))
            
            return render_template('submit_stage.html', stage=stage, event_id=event_id, stage_id=stage_id)
            
    except Exception as e:
        print(f"SUBMISSION ERROR: {e}")
        if conn: conn.rollback()
        flash("An error occurred during submission.", "danger")
        return redirect(url_for('student_registered_events'))
    finally:
        if conn: conn.close()

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
