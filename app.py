import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
import smtplib
from email.message import EmailMessage
from smtplib import SMTPAuthenticationError, SMTPConnectError
import random
from flask import jsonify
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from collections import defaultdict
import cloudinary
import cloudinary.uploader
import cloudinary.api # You might not need this for basic uploads, but good to have

# --- PostgreSQL Imports and Configuration ---
import os
import psycopg2
from psycopg2.extras import DictCursor

DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
        return conn
    except psycopg2.Error as e:
        flash(f"Database connection error: Please contact support. ({e})", "danger")
        print(f"DATABASE CONNECTION ERROR: {e}")
        return None

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')
# Use environment variable for secret key (best practice)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'code_forge_123')

# Cloudinary Configuration
cloudinary.config(
    cloud_name = os.environ.get('CLOUD_NAME'),
    api_key = os.environ.get('API_KEY'),
    api_secret = os.environ.get('API_SECRET')
)

# Allowed extensions for submissions and images (still good for client-side validation)
ALLOWED_SUBMISSION_EXTENSIONS = {'pdf', 'ppt', 'pptx', 'doc', 'docx'} # Added doc/docx
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'} # Added webp

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def get_user_by_id(user_id):
    """Fetches user data by user_id from the 'users' table."""
    conn = get_db_connection()
    if conn is None:
        return None
    
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password FROM users WHERE user_id = %s", (user_id,))
        user_data = cur.fetchone()
        if user_data:
            return dict(user_data)
        return None
    except psycopg2.Error as e:
        print(f"Database error in get_user_by_id: {e}")
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()


# -------------- Handle Submission ------------
@app.route('/submit/<int:event_id>/<int:stage_id>', methods=['GET', 'POST'])
def submit_stage(event_id, stage_id):
    """Handles student submission for a specific event stage."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('student_registered_events'))

    cur = conn.cursor()

    try:
        cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
        stage = cur.fetchone()
        if not stage:
            flash("Invalid stage", "danger")
            return redirect(url_for('student_registered_events'))

        stage_title, deadline = stage

        if datetime.now() > datetime.strptime(str(deadline), '%Y-%m-%d'):
            flash("Submission deadline has passed!", "danger")
            return redirect(url_for('student_registered_events'))

        cur.execute("SELECT id FROM submissions WHERE user_id = %s AND event_id = %s AND stage_id = %s", 
                    (session['user_id'], event_id, stage_id))
        existing_submission = cur.fetchone()

        if existing_submission:
            flash("You have already submitted. Resubmission is not allowed.", "warning")
            return redirect(url_for('student_registered_events'))

        if request.method == 'POST':
            submission_text = request.form.get('submission_text')
            file = request.files.get('submission_file')

            submission_file_url = None
            if file and file.filename and allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                try:
                    # Upload to Cloudinary. resource_type='raw' for non-image files.
                    upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder="submissions") 
                    submission_file_url = upload_result['secure_url']
                except Exception as e:
                    flash(f"Submission file upload failed: {e}", "danger")
                    print(f"CLOUDINARY SUBMISSION UPLOAD ERROR: {e}")
            elif file and file.filename and not allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                 flash("Invalid file type. Only PDF, PPT, PPTX, DOC, DOCX allowed.", "danger")
                 return render_template('submit_stage.html', stage=(stage_title, deadline), event_id=event_id, stage_id=stage_id)


            cur.execute('''
                INSERT INTO submissions (user_id, event_id, stage_id, submission_text, submission_file_url, submitted_on)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                session['user_id'], event_id, stage_id, submission_text, submission_file_url,
                datetime.now()
            ))

            conn.commit()
            flash("Submission successful!", "success")
            return redirect(url_for('student_registered_events'))

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error during submission: {e}", "danger")
        print(f"SUBMISSION ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    return render_template('submit_stage.html', stage=(stage_title, deadline), event_id=event_id, stage_id=stage_id)


# ---------- Home Page ----------
@app.route('/')
def home():
    """Renders the home page with a list of events and results."""
    conn = get_db_connection()
    if conn is None:
        return render_template('home.html', events=[], results={})

    cur = conn.cursor(cursor_factory=DictCursor)
    events = []
    grouped_results = {}

    try:
        # Fetch events
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events = cur.fetchall()

        # Fetch winners
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
            name = result_row['winner_name']
            if event_title not in grouped_results:
                grouped_results[event_title] = []
            grouped_results[event_title].append((position, name))

    except psycopg2.Error as e:
        flash(f"Error loading page data: {e}", "danger")
        print(f"HOME PAGE DATA ERROR: {e}")
        events = []
        grouped_results = {}
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
    return render_template('home.html', events=events, results=grouped_results)

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for admins, students, and mentors."""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')

        conn = get_db_connection()
        if conn is None:
            flash("Database connection failed.", "danger")
            return render_template('login.html')

        cur = conn.cursor(cursor_factory=DictCursor)

        try:
            # 1. Check in admin table
            cur.execute("SELECT username, password FROM admin WHERE username = %s", (user_id,))
            admin = cur.fetchone()
            if admin and check_password_hash(admin['password'], password):
                session['user'] = "Admin"
                session['user_id'] = admin['username']
                session['role'] = 'admin'
                flash("Admin login successful!", "success")
                return redirect(url_for('dashboard'))

            # 2. Check in users table
            cur.execute("SELECT user_id, name, role, password FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user'] = user['name']
                session['user_id'] = user['user_id']
                session['role'] = user['role']
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))

            # 3. Check in mentors table
            cur.execute("SELECT user_id, name, password FROM mentors WHERE user_id = %s", (user_id,))
            mentor = cur.fetchone()
            if mentor and check_password_hash(mentor['password'], password):
                session['user'] = mentor['name']
                session['user_id'] = mentor['user_id']
                session['role'] = 'mentor'
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))

            flash("Invalid User ID or Password", "danger")

        except psycopg2.Error as e:
            flash(f"Database error during login: {e}", "danger")
            print(f"LOGIN ERROR: {e}")
        finally:
            if cur: cur.close()
            if conn: conn.close()

    return render_template('login.html')


# ---------- OTP Function ----------
def send_otp(receiver_email, otp):
    """Sends an OTP to the specified email address."""
    EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("[CONFIG ERROR] Email credentials not set in environment variables (EMAIL_USER, EMAIL_PASS).")
        flash("Email sending failed: Server not configured. Contact admin.", "danger")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'OTP Verification - College Club'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your OTP is: {otp}\n\nThis OTP is valid for 10 minutes.\nDo not share it with anyone.')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[SUCCESS] OTP sent to {receiver_email}")
        flash("OTP sent to your email!", "info")
        return True

    except SMTPAuthenticationError as e:
        print(f"[AUTH ERROR] Email or password incorrect. Use Gmail App Password if 2FA is enabled. Error: {e}")
        flash("Email sending failed: Authentication error. Check server logs.", "danger")
    except SMTPConnectError as e:
        print(f"[CONNECTION ERROR] Could not connect to the email server. Check server address, port, and network. Error: {e}")
        flash("Email sending failed: Connection error. Check server logs.", "danger")
    except Exception as e:
        print(f"[GENERAL ERROR] Failed to send OTP to {receiver_email}. Error: {e}")
        flash("Something went wrong while sending OTP. Please try again.", "danger")
    return False

# --- NEW FUNCTION: Send Welcome Email ---
def send_welcome_email(receiver_email, name, user_id):
    """Sends a welcome email with the user's ID upon registration."""
    EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("[CONFIG ERROR] Email credentials not set for welcome email.")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'Welcome to Code Forge! 🎉'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'''Hi {name},

Welcome to the Code Forge community! We're thrilled to have you on board.

Your journey to innovate, collaborate, and create starts now. Here is your unique User ID for logging in:

User ID: {user_id}

Keep it safe! We can't wait to see what you'll build with us.

Best,
The Code Forge Team
''')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[SUCCESS] Welcome email sent to {receiver_email}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send welcome email to {receiver_email}. Error: {e}")
    return False
# --- END NEW FUNCTION ---

@app.route('/view_all_users')
def view_all_users():
    """Displays a list of all users (students and mentors) for admin."""
    if 'role' not in session or session['role'] != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('view_all_users.html', users=[], mentors=[])

    cur = conn.cursor(cursor_factory=DictCursor)
    all_users = []
    all_mentors = []

    try:
        cur.execute("SELECT user_id, name, college, email, role, contact FROM users ORDER BY name ASC")
        all_users = cur.fetchall()

        cur.execute("SELECT user_id, name, college, email, expertise FROM mentors ORDER BY name ASC")
        all_mentors = cur.fetchall()

    except psycopg2.Error as e:
        flash(f"Database error fetching users: {e}", "danger")
        print(f"VIEW ALL USERS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('view_all_users.html', users=all_users, mentors=all_mentors)


@app.route('/delete_event/<int:event_id>', methods=['GET', 'POST'])
def delete_event(event_id):
    """Handles the deletion of an event and its associated data."""
    if 'role' not in session or session['role'] != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Cannot delete event.", "danger")
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=DictCursor) # Use DictCursor to get event title/url

    try:
        # Get event title and image_url to potentially delete from Cloudinary if desired
        cur.execute("SELECT title, image_url FROM events WHERE id = %s", (event_id,))
        event_info = cur.fetchone()
        

        # Delete event results (linked by event_title, not event_id)
        if event_info: # Only delete if event_info was found
            cur.execute("DELETE FROM event_results WHERE event_title = %s", (event_info['title'],))
        
        # Delete the event itself (cascades to stages, registrations, submissions)
        cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
        
        conn.commit()
        flash("Event and all associated data deleted successfully!", "success")

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error deleting event: {e}", "danger")
        print(f"DELETE EVENT ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return redirect(url_for('admin_dashboard'))


# ---------- Student Registration Step 1 ----------
@app.route('/register_student', methods=['GET', 'POST'])
def register_student():
    """Handles the first step of student registration (collects basic info and sends OTP)."""
    if request.method == 'POST':
        name = request.form['name']
        college = request.form['college']
        roll_no = request.form['roll_no']
        email = request.form['email']
        otp_input = request.form.get('otp')

        session['name'] = name
        session['college'] = college
        session['roll_no'] = roll_no
        session['email'] = email

        if "marwadi" not in college.lower():
            if otp_input:
                if otp_input == session.get('otp'):
                    flash("OTP Verified", "success")
                    return redirect(url_for('register_details'))
                else:
                    flash("Invalid OTP", "danger")
                    return render_template('register_step1.html', show_otp=True)
            else:
                otp = str(random.randint(100000, 999999))
                session['otp'] = otp
                send_otp(email, otp)
                return render_template('register_step1.html', show_otp=True)
        else:
            return redirect(url_for('register_details'))

    return render_template('register_step1.html', show_otp=False)

# ---------- Student Registration Step 2 ----------
@app.route('/register_details', methods=['GET', 'POST'])
def register_details():
    """Handles the second step of student registration (collects detailed info and saves to DB)."""
    if request.method == 'POST':
        address = request.form['address']
        contact = request.form['contact']
        year = request.form['year']
        branch = request.form['branch']
        department = request.form['department']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template('register_details.html')

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())[:8]

        conn = get_db_connection()
        if conn is None:
            return render_template('register_details.html')

        cur = conn.cursor()
        try:
            cur.execute('''INSERT INTO users 
                (user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                (
                    user_id,
                    session['name'],
                    session['college'],
                    session['roll_no'],
                    session['email'],
                    address,
                    contact,
                    'student',
                    year,
                    branch,
                    department,
                    hashed_password
                )
            )
            conn.commit()

            # --- ADDED: Send welcome email after successful registration ---
            send_welcome_email(session['email'], session['name'], user_id)
            # ----------------------------------------------------------------

            session['user'] = session['name']
            session['user_id'] = user_id
            session['role'] = 'student'
            flash(f"Student Registration complete! Your User ID is {user_id}", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            flash(f"Registration failed: {e}", "danger")
            print(f"STUDENT REGISTRATION ERROR: {e}")
        finally:
            if cur: cur.close()
            if conn: conn.close()

    return render_template('register_details.html')

# ---------- Mentor Registration ----------
@app.route('/register_mentor', methods=['GET', 'POST'])
def register_mentor():
    """Handles mentor registration and saves to DB."""
    if request.method == 'POST':
        name = request.form['name']
        college = request.form['college']
        email = request.form['email']
        expertise = request.form['expertise']
        skills = request.form['skills']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template('register_mentor.html')

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())[:8]

        conn = get_db_connection()
        if conn is None:
            return render_template('register_mentor.html')

        cur = conn.cursor()
        try:
            cur.execute('''INSERT INTO mentors 
                (user_id, name, college, email, expertise, skills, password)
                VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (user_id, name, college, email, expertise, skills, hashed_password)
            )
            conn.commit()

            # --- ADDED: Send welcome email after successful registration ---
            send_welcome_email(email, name, user_id)
            # ----------------------------------------------------------------

            session['user'] = name
            session['user_id'] = user_id
            session['role'] = 'mentor'
            flash(f"Mentor Registration complete! Your User ID is {user_id}", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            flash(f"Registration failed: {e}", "danger")
            print(f"MENTOR REGISTRATION ERROR: {e}")
        finally:
            if cur: cur.close()
            if conn: conn.close()

    return render_template('register_mentor.html')

# ---------- Dashboard ----------
@app.route('/dashboard')
def dashboard():
    """Redirects to the appropriate dashboard based on user role."""
    if 'user' in session:
        role = session.get('role')
        if role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'admin':
            return redirect(url_for('admin_dashboard'))
        if role == 'mentor':
            return redirect(url_for('mentor_dashboard'))
    return redirect(url_for('login'))


@app.route('/mentor_dashboard')
def mentor_dashboard():
    """Renders the mentor dashboard with events, rooms, and results."""
    if 'user' not in session or session.get('role') != 'mentor':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('mentor_dashboard.html', events=[], brainstorm_rooms=[], results={})

    cur = conn.cursor(cursor_factory=DictCursor) 

    events_for_template = []
    rooms = []
    processed_results = defaultdict(list)

    try:
        # Get all events with full description and image URL
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events_raw = cur.fetchall()

        for event_row in events_raw:
            event_id = event_row['id']
            event_data = {
                'id': event_id,
                'title': event_row['title'],
                'description': event_row['description'],
                'date': event_row['date'],
                'short_description': event_row['short_description'],
                'image_url': event_row['image_url'], # Fetch image_url
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

        # Get all brainstorm rooms
        cur.execute("SELECT room_id, title, created_by FROM brainstorm_rooms ORDER BY created_at DESC")
        rooms = cur.fetchall()

        # Get result announcements
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
        if cur: cur.close()
        if conn: conn.close()

    return render_template('mentor_dashboard.html',
                           events=events_for_template,
                           brainstorm_rooms=rooms,
                           results=dict(processed_results),
                           role=session.get('role'))


@app.route('/announce_winner', methods=['POST'])
def announce_winner():
    """Handles announcing winners for an event (admin only)."""
    if 'role' not in session or session['role'] != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    event_title = request.form['event_title']
    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor()

    try:
        # Simplified loop to get only name and position
        for i in range(1, 4):
            position = request.form.get(f'position{i}')
            name = request.form.get(f'name{i}')

            # Check if a name was provided for the position
            if name:
                # Updated SQL query to insert only the necessary fields
                cur.execute('''
                    INSERT INTO event_results (event_title, position, winner_name)
                    VALUES (%s, %s, %s)
                ''', (event_title, position, name))

        conn.commit()
        flash("Winners announced successfully!", "success")
    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error announcing winners: {e}", "danger")
        print(f"ANNOUNCE WINNER ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    return redirect(url_for('admin_dashboard'))


@app.route('/event/<int:event_id>', methods=['GET', 'POST'])
def event_detail(event_id):
    """Displays event details and handles student registration for an event."""
    if 'user' not in session or session.get('role') != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('event_detail.html', event=None, registered=False)

    cur = conn.cursor(cursor_factory=DictCursor)
    event = None
    already_registered = False

    try:
        # Fetch event info - select image_url
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events WHERE id = %s", (event_id,))
        event = cur.fetchone()

        cur.execute("SELECT id FROM event_registrations WHERE user_id = %s AND event_id = %s", 
                    (session['user_id'], event_id))
        already_registered = cur.fetchone()

        if request.method == 'POST' and not already_registered:
            cur.execute("INSERT INTO event_registrations (user_id, event_id) VALUES (%s, %s)",
                        (session['user_id'], event_id))
            conn.commit()
            flash("You have successfully registered for this event!", "success")
            return redirect(url_for('student_registered_events'))

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error on event detail page: {e}", "danger")
        print(f"EVENT DETAIL ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
    return render_template('event_detail.html', event=event, registered=already_registered)

# ---------- Registered Event ----------
@app.route('/registered_events')
def student_registered_events():
    """Displays events a student is registered for, along with submission status."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('registered_events.html', events=[])

    cur = conn.cursor(cursor_factory=DictCursor)
    events_with_stages_and_submissions = []

    try:
        # Get all events the student is registered for - select image_url
        cur.execute('''
            SELECT e.id, e.title, e.description, e.date, e.short_description, e.image_url
            FROM event_registrations r
            JOIN events e ON r.event_id = e.id
            WHERE r.user_id = %s
            ORDER BY e.date DESC
        ''', (session['user_id'],))

        registered_events_raw = cur.fetchall()

        for event_row in registered_events_raw:
            event_id = event_row['id']
            event_data = {
                'id': event_row['id'],
                'title': event_row['title'],
                'description': event_row['description'],
                'date': event_row['date'],
                'short_description': event_row['short_description'],
                'image_url': event_row['image_url'], # Fetch image_url
                'stages': []
            }

            cur.execute("SELECT id, stage_title, deadline FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
            stages_for_event = cur.fetchall()

            for stage_row in stages_for_event:
                stage_id = stage_row['id']
                # Select submission_file_url
                cur.execute('''
                    SELECT submission_text, submission_file_url, submitted_on
                    FROM submissions
                    WHERE user_id = %s AND event_id = %s AND stage_id = %s
                ''', (session['user_id'], event_id, stage_id))
                submission_info = cur.fetchone()

                stage_details = {
                    'id': stage_id,
                    'stage_title': stage_row['stage_title'],
                    'deadline': stage_row['deadline'],
                    'submission_text': submission_info['submission_text'] if submission_info else None,
                    'submission_file_url': submission_info['submission_file_url'] if submission_info else None, # Fetch submission_file_url
                    'submitted_on': submission_info['submitted_on'] if submission_info else None,
                    'status': 'Submitted' if submission_info else 'Not Submitted'
                }
                event_data['stages'].append(stage_details)

            events_with_stages_and_submissions.append(event_data)

    except psycopg2.Error as e:
        flash(f"Database error fetching registered events: {e}", "danger")
        print(f"REGISTERED EVENTS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('registered_events.html', events=events_with_stages_and_submissions)


# ---------- Admin ----------
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Renders the admin dashboard, handles event creation, and displays event statistics."""
    if 'user' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('admin_dashboard.html', event_stats=[])

    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            date = request.form['date']
            short_desc = request.form['short_description']
            image_file = request.files.get('event_image')
            
            image_url = None
            if image_file and image_file.filename and allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                try:
                    upload_result = cloudinary.uploader.upload(image_file, folder="event_images") 
                    image_url = upload_result['secure_url']
                except Exception as e:
                    flash(f"Event image upload failed: {e}", "danger")
                    print(f"CLOUDINARY EVENT IMAGE UPLOAD ERROR: {e}")
            elif image_file and image_file.filename and not allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                flash("Invalid image file type. Only PNG, JPG, JPEG, GIF, WEBP allowed.", "danger")

            # Insert new event - use image_url
            cur.execute('''INSERT INTO events (title, short_description, description, date, image_url)
                            VALUES (%s, %s, %s, %s, %s) RETURNING id''', 
                        (title, short_desc, description, date, image_url))
            event_id = cur.fetchone()['id']

            stages = request.form.getlist('stage_title[]')
            deadlines = request.form.getlist('deadline[]')

            for stage_title, deadline in zip(stages, deadlines):
                cur.execute('INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)',
                            (event_id, stage_title, deadline))

            conn.commit()
            flash("Hackathon with stages created successfully!", "success")

        # Get all events for display - select image_url
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events = cur.fetchall()

        event_stats = []
        for event_row in events:
            event_id = event_row['id']

            cur.execute("SELECT COUNT(*) FROM event_registrations WHERE event_id = %s", (event_id,))
            registered = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM submissions WHERE event_id = %s", (event_id,))
            submitted = cur.fetchone()[0]

            event_stats.append({
                'event': event_row,
                'registered': registered,
                'submitted': submitted
            })

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error on admin dashboard: {e}", "danger")
        print(f"ADMIN DASHBOARD ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('admin_dashboard.html', event_stats=event_stats)

# ---------- progress ----------
@app.route('/view_progress/<int:event_id>')
def view_progress(event_id):
    """Displays the progress of participants for a given event."""
    if 'user' not in session or session.get('role') not in ['admin', 'mentor']:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=DictCursor)
    progress = []
    stages = []

    try:
        cur.execute("SELECT id, stage_title FROM event_stages WHERE event_id = %s", (event_id,))
        stage_data = cur.fetchall()

        if not stage_data:
            flash("No stages found for this event.", "warning")
            return redirect(url_for('admin_dashboard'))

        stages = [row['stage_title'] for row in stage_data]
        stage_id_map = {row['stage_title']: row['id'] for row in stage_data}

        cur.execute('''
            SELECT u.user_id, u.name, u.email, u.college, u.roll_no
            FROM event_registrations r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.event_id = %s
        ''', (event_id,))
        participants = cur.fetchall()

        for user_row in participants:
            user_id = user_row['user_id']
            user_info = {
                'user_id': user_id,
                'name': user_row['name'],
                'email': user_row['email'],
                'college': user_row['college'],
                'roll_no': user_row['roll_no'],
                'stage_status': {}
            }

            for stage_title in stages:
                stage_id = stage_id_map[stage_title]

                # Select submission_file_url
                cur.execute('''
                    SELECT submission_file_url FROM submissions 
                    WHERE event_id = %s AND user_id = %s AND stage_id = %s
                ''', (event_id, user_id, stage_id))
                result = cur.fetchone()

                if result and result['submission_file_url']:
                    file_url = result['submission_file_url']
                    user_info['stage_status'][stage_title] = {
                        'status': '', 
                        'file': file_url # This is now a URL
                    }
                else:
                    user_info['stage_status'][stage_title] = {
                        'status': '❌',
                        'file': None
                    }

            progress.append(user_info)

    except psycopg2.Error as e:
        flash(f"Database error viewing progress: {e}", "danger")
        print(f"VIEW PROGRESS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    return render_template('view_progress.html', progress=progress, stages=stages, event_id=event_id)


@app.route('/brainstorm', methods=['GET', 'POST'])
def brainstorm():
    if 'user_id' not in session or session['role'] not in ['student', 'mentor']:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Please contact support.", "danger")
        return render_template('brainstorm.html', rooms=[])

    cur = conn.cursor(cursor_factory=DictCursor) # Keep DictCursor here
    rooms_data = []

    try:
        if request.method == 'POST':
            room_title = request.form['room_title']
            if not room_title:
                flash("Room title cannot be empty.", "danger")
                return redirect(url_for('brainstorm'))

            room_id = str(uuid.uuid4())[:8]
            created_by = session['user_id']
            created_at = datetime.now()

            cur.execute('''
                INSERT INTO brainstorm_rooms (room_id, title, created_by, created_at)
                VALUES (%s, %s, %s, %s)
            ''', (room_id, room_title, created_by, created_at))

            conn.commit()
            flash("Room created! Share the invite link.", "success")
            return redirect(url_for('join_brainstorm_room', room_id=room_id))

        # --- IMPORTANT CHANGE HERE ---
        # Fetching creator name using LEFT JOIN and COALESCE
        cur.execute('''
            SELECT 
                br.room_id, 
                br.title, 
                br.created_at,
                COALESCE(u.name, m.name, 'Unknown User') AS creator_name
            FROM brainstorm_rooms br
            LEFT JOIN users u ON br.created_by = u.user_id
            LEFT JOIN mentors m ON br.created_by = m.user_id
            ORDER BY br.created_at DESC
        ''')
        rooms_data = [dict(r) for r in cur.fetchall()] # Convert DictRows to dicts for template
    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error on brainstorm page: {e}", "danger")
        print(f"BRAINSTORM ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('brainstorm.html', rooms=rooms_data)


@app.route('/brainstorm/room/<room_id>')
def join_brainstorm_room(room_id):
    """Renders the brainstorm room, displaying chat history and shared files."""
    if 'user_id' not in session:
        flash("Login required", "danger")
        return redirect(url_for('login'))

    user = session.get("user") 

    conn = get_db_connection()
    if conn is None:
        return render_template('brainstorm_room.html', room_id=room_id, user=user, shared_files=[], chat_history=[], admin_name="Database Error")

    cur = conn.cursor(cursor_factory=DictCursor)
    chat_history = []
    shared_files_data = [] # New list for persistent shared files
    creator_id = None
    admin_name = "Unknown"

    try:
        cur.execute("SELECT username, message, timestamp FROM brainstorm_chats WHERE room_id = %s ORDER BY timestamp ASC", (room_id,))
        chat_history = cur.fetchall()

        # Fetch shared files for this room from the database
        cur.execute("SELECT filename, file_url, uploaded_by_user, uploaded_at FROM brainstorm_room_files WHERE room_id = %s ORDER BY uploaded_at ASC", (room_id,))
        shared_files_data = cur.fetchall()

        cur.execute("SELECT created_by FROM brainstorm_rooms WHERE room_id = %s", (room_id,))
        creator_result = cur.fetchone()
        creator_id = creator_result['created_by'] if creator_result else None

        if creator_id:
            cur.execute("SELECT name FROM users WHERE user_id = %s", (creator_id,))
            admin_result = cur.fetchone()
            if admin_result:
                admin_name = admin_result['name']
            else:
                cur.execute("SELECT name FROM mentors WHERE user_id = %s", (creator_id,))
                mentor_admin_result = cur.fetchone()
                if mentor_admin_result:
                    admin_name = mentor_admin_result['name']

    except psycopg2.Error as e:
        flash(f"Database error in brainstorm room: {e}", "danger")
        print(f"BRAINSTORM ROOM ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('brainstorm_room.html',
                           room_id=room_id,
                           user=user,
                           shared_files=shared_files_data, # Pass persistent shared files
                           chat_history=chat_history,
                           admin_name=admin_name,
                           role=session.get('role')) # Pass role for dynamic button logic in template


@app.route('/student_dashboard')
def student_dashboard():
    """Renders the student dashboard with personal info, events, and results."""
    if 'user' not in session or session.get('role') != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('student_dashboard.html', student=None, events=[], results={})

    cur = conn.cursor(cursor_factory=DictCursor)
    student = None
    events = []
    grouped_results = {}

    try:
        cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department FROM users WHERE user_id = %s", (session['user_id'],))
        student = cur.fetchone()

        # Get all events - select image_url
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events = cur.fetchall()

        # CORRECTED: Fetch winner_email as well to match the template
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
            email = result_row.get('winner_email', '') # Use .get() for safety
            if event_title not in grouped_results:
                grouped_results[event_title] = []
            grouped_results[event_title].append((position, name, email))

    except psycopg2.Error as e:
        flash(f"Database error on student dashboard: {e}", "danger")
        print(f"STUDENT DASHBOARD ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('student_dashboard.html', student=student, events=events, results=grouped_results, role=session.get('role'))


@app.route('/brainstorm/upload/<room>', methods=['POST'])
def upload_file_brainstorm(room):
    """Handles file uploads to brainstorm rooms. Persists metadata to PostgreSQL and file to Cloudinary."""
    file = request.files['file']
    user_who_uploaded = request.form.get('user')
    
    if not file or not user_who_uploaded:
        return jsonify(status='error', message="No file or user provided for upload.")

    if not allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS): # Using submission extensions for brainstorm files
        return jsonify(status='error', message="Invalid file type. Only PDF, PPT, PPTX, DOC, DOCX allowed for brainstorm files.")

    try:
        # Upload to Cloudinary. resource_type='raw' for non-image files.
        upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder=f"brainstorm_rooms/{room}") 
        file_url = upload_result['secure_url']
        filename = file.filename # Use original filename for display

        conn = get_db_connection()
        if conn is None:
            return jsonify(status='error', message="Database connection failed for file persistence.")
        cur = conn.cursor()
        try:
            # Save file metadata to the new brainstorm_room_files table
            cur.execute('''
                INSERT INTO brainstorm_room_files (room_id, filename, file_url, uploaded_by_user, uploaded_at)
                VALUES (%s, %s, %s, %s, %s)
            ''', (room, filename, file_url, user_who_uploaded, datetime.now()))
            conn.commit()
        except psycopg2.Error as e:
            conn.rollback()
            print(f"DATABASE ERROR SAVING BRAINSTORM FILE METADATA: {e}")
            return jsonify(status='error', message=f"Failed to save file metadata to DB: {e}")
        finally:
            if cur: cur.close()
            if conn: conn.close()

        # Return success with necessary data for client-side update
        return jsonify(status='success', filename=filename, file_url=file_url, user=user_who_uploaded, timestamp=datetime.now().isoformat())
    except Exception as e:
        print(f"Cloudinary file upload error: {e}")
        return jsonify(status='error', message=f"Failed to upload file to Cloudinary: {e}")


@app.route('/brainstorm/files/<room>')
def get_shared_files(room):
    """Returns a JSON list of files shared in a brainstorm room (from DB)."""
    conn = get_db_connection()
    if conn is None:
        return jsonify(status='error', message="Database connection failed to fetch files.")
    cur = conn.cursor(cursor_factory=DictCursor)
    files_data = []
    try:
        # Fetch file metadata from the new brainstorm_room_files table
        cur.execute("SELECT filename, file_url, uploaded_by_user, uploaded_at FROM brainstorm_room_files WHERE room_id = %s ORDER BY uploaded_at ASC", (room,))
        files_data = cur.fetchall()
        # Convert DictRows to plain dictionaries for jsonify if necessary (DictCursor often handles this)
        files_data = [dict(row) for row in files_data]
    except psycopg2.Error as e:
        print(f"DATABASE ERROR FETCHING BRAINSTORM FILES: {e}")
        return jsonify(status='error', message=f"Failed to fetch files from DB: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    return jsonify(files_data)


@app.route('/brainstorm/create', methods=['POST'])
def create_room():
    """Handles creating a new brainstorm room."""
    # This route is a bit redundant with the POST logic in /brainstorm, consider consolidating.
    if 'user_id' not in session or session['role'] != 'student': # Only students create rooms
        flash("Unauthorized access to create room", "danger")
        return redirect(url_for('dashboard')) # Redirect to appropriate dashboard

    room_id = str(uuid.uuid4())[:8]
    created_by = session['user_id']
    created_at = datetime.now()

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Room creation failed.", "danger")
        return redirect(url_for('brainstorm'))

    cur = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO brainstorm_rooms (room_id, title, created_by, created_at)
            VALUES (%s, %s, %s, %s)
        ''', (room_id, "New Brainstorm Room", created_by, created_at)) # Default title, user can rename
        conn.commit()
        flash(f"Room created! Share the invite link: /brainstorm/room/{room_id}", "success")
        return redirect(url_for('join_brainstorm_room', room_id=room_id))
    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error creating room: {e}", "danger")
        print(f"BRAINSTORM ROOM CREATE ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    return redirect(url_for('brainstorm')) # Fallback redirect


@socketio.on('join')
def handle_join(data):
    """Handles a user joining a SocketIO room."""
    room = data.get('room')
    user = data.get('user', 'Anonymous')
    if room and user:
        join_room(room)
        emit('message', {'user': 'System', 'msg': f"{user} joined the room.", 'timestamp': datetime.now().isoformat()}, to=room)
    else:
        print("Invalid data for join event:", data)


@socketio.on('send_message')
def handle_message(data):
    """Handles sending and saving chat messages in a brainstorm room."""
    room = data.get('room')
    user = data.get('user')
    msg = data.get('msg')
    timestamp = data.get('timestamp')

    if not all([room, user, msg]):
        print("Invalid message data:", data)
        return

    conn = get_db_connection()
    if conn is None:
        return
    
    cur = conn.cursor()
    try:
        db_timestamp = datetime.fromisoformat(timestamp) if timestamp else datetime.now()
        cur.execute("INSERT INTO brainstorm_chats (room_id, username, message, timestamp) VALUES (%s, %s, %s, %s)", 
                    (room, user, msg, db_timestamp))
        conn.commit()
        emit('message', {'user': user, 'msg': msg, 'timestamp': timestamp}, to=room)
    except psycopg2.Error as e:
        conn.rollback()
        print(f"CHAT MESSAGE SAVE ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

@socketio.on('share_file')
def handle_share_file(data):
    """Handles real-time notification of a file being shared in a brainstorm room."""
    room = data.get('room')
    user = data.get('user')
    filename = data.get('filename')
    file_url = data.get('file_url')
    timestamp = data.get('timestamp')

    if not all([room, user, filename, file_url, timestamp]):
        print("Invalid file share data:", data)
        return
    
    emit('file_shared', {'user': user, 'filename': filename, 'file_url': file_url, 'timestamp': timestamp}, to=room)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Displays and allows updating of student user profile."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access. Please log in as a student.", "danger")
        return redirect(url_for('login'))

    user_data = get_user_by_id(session['user_id'])
    if not user_data:
        flash("User data not found. Please log in again.", "danger")
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        contact = request.form.get('contact')
        address = request.form.get('address')
        year = request.form.get('year')
        branch = request.form.get('branch')
        department = request.form.get('department')

        conn = get_db_connection()
        if conn is None:
            return render_template('profile.html', user_data=user_data)

        cur = conn.cursor()
        try:
            cur.execute('''
                UPDATE users
                SET contact = %s, address = %s, year = %s, branch = %s, department = %s
                WHERE user_id = %s
            ''', (contact, address, year, branch, department, session['user_id']))
            conn.commit()
            flash("Profile updated successfully!", "success")
            user_data = get_user_by_id(session['user_id'])
        except psycopg2.Error as e:
            conn.rollback()
            flash(f"Database error during profile update: {e}", "danger")
            print(f"PROFILE UPDATE ERROR: {e}")
        finally:
            if cur: cur.close()
            if conn: conn.close()

    return render_template('profile.html', user_data=user_data)

@app.route('/change_password', methods=['POST'])
def change_password():
    """Allows student users to change their password."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access. Please log in as a student.", "danger")
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    user_data = get_user_by_id(session['user_id'])
    if not user_data:
        flash("User data not found. Please log in again.", "danger")
        session.clear()
        return redirect(url_for('login'))

    if not check_password_hash(user_data['password'], current_password):
        flash("Current password incorrect.", "danger")
        return redirect(url_for('profile'))

    if new_password != confirm_new_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))

    if len(new_password) < 6:
        flash("New password must be at least 6 characters long.", "danger")
        return redirect(url_for('profile'))

    hashed_new_password = generate_password_hash(new_password)

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('profile'))

    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET password = %s WHERE user_id = %s", (hashed_new_password, session['user_id']))
        conn.commit()
        flash("Password changed successfully!", "success")
    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error during password change: {e}", "danger")
        print(f"CHANGE PASSWORD ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return redirect(url_for('profile'))

# ---------- Logout ----------
@app.route('/logout')
def logout():
    """Logs out the current user and clears the session."""
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# ---------- Run App ----------
if __name__ == '__main__':
    socketio.run(app, debug=True)