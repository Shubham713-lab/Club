import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.security import check_password_hash, generate_password_hash
import uuid
import smtplib
from email.message import EmailMessage
from smtplib import SMTPAuthenticationError, SMTPConnectError
import random
from flask import jsonify
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from collections import defaultdict

# --- NEW: PostgreSQL Imports and Configuration ---
import os
import psycopg2
from psycopg2.extras import DictCursor

DATABASE_URL = os.getenv("DATABASE_URL")

conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)

# PostgreSQL Database connection details - MAKE SURE TO UPDATE DB_PASSWORD
DB_NAME = "my_app_db"
DB_USER = "myuser"
DB_PASSWORD = "8080" # <--- IMPORTANT: REPLACE THIS WITH YOUR ACTUAL PASSWORD!
DB_HOST = "localhost"
DB_PORT = "5432" # Default PostgreSQL port

# --- Hardcoded Admin Credentials (FOR DEMONSTRATION/TESTING ONLY - NOT RECOMMENDED FOR PRODUCTION) ---
HARDCODED_ADMIN_USERNAME = "admin001"
HARDCODED_ADMIN_PASSWORD = "admin123" # This is the plaintext password
# --- END Hardcoded Admin Credentials ---


def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except psycopg2.Error as e:
        # Flash a message to the user and print error for debugging
        flash(f"Database connection error: Please contact support. ({e})", "danger")
        print(f"DATABASE CONNECTION ERROR: {e}")
        return None

# --- END NEW: PostgreSQL Imports and Configuration ---

# In-memory store for shared files (per room) - Note: these will reset on server restart
# For persistence, you'd need to store this data in your PostgreSQL DB (e.g., in a brainstorm_files table)
shared_files = {}
rooms = {}

def get_user_by_id(user_id):
    """Fetches user data by user_id from the 'users' table."""
    conn = get_db_connection()
    if conn is None:
        return None
    
    # Use DictCursor to get results as dictionaries for easier access
    cur = conn.cursor(cursor_factory=DictCursor)
    
    try:
        # Use %s placeholder for psycopg2
        cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password FROM users WHERE user_id = %s", (user_id,))
        user_data = cur.fetchone()
        
        if user_data:
            # DictCursor already returns a dict-like object, convert to actual dict if needed
            return dict(user_data)
        return None
    except psycopg2.Error as e:
        print(f"Database error in get_user_by_id: {e}")
        return None
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')
app.secret_key = 'shubham_secret_123'

# ----------- for submission ------------
UPLOAD_SUBMISSION_FOLDER = 'uploads'  # for files
app.config['UPLOAD_SUBMISSION_FOLDER'] = UPLOAD_SUBMISSION_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'ppt', 'pptx'}

if not os.path.exists(UPLOAD_SUBMISSION_FOLDER):
    os.makedirs(UPLOAD_SUBMISSION_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- for image --------------
UPLOAD_IMAGE_FOLDER = os.path.join('static', 'uploads')  # for images
if not os.path.exists(UPLOAD_IMAGE_FOLDER):
    os.makedirs(UPLOAD_IMAGE_FOLDER)
app.config['UPLOAD_IMAGE_FOLDER'] = UPLOAD_IMAGE_FOLDER
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

# Brainstorm Room Directory
BRAINSTORM_FOLDER = 'brainstorm_uploads'
if not os.path.exists(BRAINSTORM_FOLDER):
    os.makedirs(BRAINSTORM_FOLDER)

# --- RENAMED ROUTE FOR BRAINSTORM FILE DOWNLOAD (resolves conflict with download_submission) ---
@app.route('/download_brainstorm_file/<path:filename>')
def download_brainstorm_file(filename):
    """Serves files uploaded in brainstorm rooms."""
    print(f"DEBUG: Attempting to serve brainstorm file: {filename} from {BRAINSTORM_FOLDER}")
    full_path = os.path.join(BRAINSTORM_FOLDER, filename)
    if not os.path.isfile(full_path):
        print(f"DEBUG: Brainstorm file not found: {full_path}")
        abort(404)
    return send_from_directory(BRAINSTORM_FOLDER, filename, as_attachment=True)


# --- ROUTE FOR EVENT SUBMISSION DOWNLOAD (Original name kept for existing links) ---
@app.route('/download_submission/<path:filename>')
def download_submission(filename):
    """Serves submission files for events."""
    print(f"DEBUG: Attempting to serve submission file: {filename} from {app.config['UPLOAD_SUBMISSION_FOLDER']}")
    full_path = os.path.join(app.config['UPLOAD_SUBMISSION_FOLDER'], filename)
    if not os.path.isfile(full_path):
        print(f"DEBUG: Submission file not found: {full_path}")
        abort(404)
    return send_from_directory(app.config['UPLOAD_SUBMISSION_FOLDER'], filename, as_attachment=True)


# -------------- Handle Submission ------------
@app.route('/submit/<int:event_id>/<int:stage_id>', methods=['GET', 'POST'])
def submit_stage(event_id, stage_id):
    """Handles student submission for a specific event stage."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('student_registered_events')) # Redirect on connection failure

    cur = conn.cursor()

    try:
        # Get stage info - use %s
        cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
        stage = cur.fetchone()
        if not stage:
            flash("Invalid stage", "danger")
            return redirect(url_for('student_registered_events'))

        stage_title, deadline = stage

        # Check if deadline passed
        # Assuming deadline from DB is already a datetime.date object or similar compatible with strftime
        if datetime.now() > datetime.strptime(str(deadline), '%Y-%m-%d'): # Convert date object to string if needed
            flash("Submission deadline has passed!", "danger")
            return redirect(url_for('student_registered_events'))

        # Check if already submitted - use %s
        cur.execute("SELECT id FROM submissions WHERE user_id = %s AND event_id = %s AND stage_id = %s", 
                    (session['user_id'], event_id, stage_id))
        existing_submission = cur.fetchone()

        if existing_submission:
            flash("You have already submitted. Resubmission is not allowed.", "warning")
            return redirect(url_for('student_registered_events'))

        # Allow submission only if not submitted yet
        if request.method == 'POST':
            submission_text = request.form.get('submission_text')
            file = request.files.get('submission_file')

            file_path = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = filename  # Store only the filename in DB
                file.save(os.path.join(app.config['UPLOAD_SUBMISSION_FOLDER'], filename))

            # Insert into submissions - use %s
            cur.execute('''
                INSERT INTO submissions (user_id, event_id, stage_id, submission_text, submission_file, submitted_on)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                session['user_id'], event_id, stage_id, submission_text, file_path,
                datetime.now() # psycopg2 can handle datetime objects directly
            ))

            conn.commit()
            flash("Submission successful!", "success")
            return redirect(url_for('student_registered_events'))

    except psycopg2.Error as e:
        conn.rollback() # Rollback changes if an error occurs
        flash(f"Database error during submission: {e}", "danger")
        print(f"SUBMISSION ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    return render_template('submit_stage.html', stage=(stage_title, deadline), event_id=event_id, stage_id=stage_id)


# ---------- Home Page ----------
@app.route('/')
def home():
    """Renders the home page with a list of events."""
    conn = get_db_connection()
    if conn is None:
        return render_template('home.html', events=[]) # Pass empty list on failure

    cur = conn.cursor()
    try:
        cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
        events = cur.fetchall()
    except psycopg2.Error as e:
        flash(f"Error loading events: {e}", "danger")
        print(f"HOME PAGE EVENTS ERROR: {e}")
        events = []
    finally:
        if cur: cur.close()
        if conn: conn.close()
    return render_template('home.html', events=events)

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for students, admins, and mentors."""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')

        # --- START: Hardcoded Admin Login (FOR TESTING ONLY) ---
        if user_id == HARDCODED_ADMIN_USERNAME and password == HARDCODED_ADMIN_PASSWORD:
            session['user'] = "Hardcoded Admin" # Or any name you prefer for this hardcoded admin
            session['user_id'] = HARDCODED_ADMIN_USERNAME
            session['role'] = 'admin'
            flash("Hardcoded Admin Login successful!", "success")
            return redirect(url_for('dashboard'))
        # --- END: Hardcoded Admin Login ---


        conn = get_db_connection()
        if conn is None:
            return render_template('login.html')

        cur = conn.cursor(cursor_factory=DictCursor) # Use DictCursor for easier column access

        try:
            # Try user from `users` table (this will now be for other users, as hardcoded admin is handled above)
            cur.execute("SELECT user_id, name, role, password FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()

            if user:
                hashed_password = user['password'] # Access by key
                if check_password_hash(hashed_password, password):
                    session['user'] = user['name']
                    session['user_id'] = user['user_id']
                    session['role'] = user['role']
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))
            else:
                # Try mentor from `mentors` table
                cur.execute("SELECT user_id, name, password FROM mentors WHERE user_id = %s", (user_id,))
                mentor = cur.fetchone()

                if mentor and check_password_hash(mentor['password'], password): # Access by key
                    session['user'] = mentor['name']
                    session['user_id'] = mentor['user_id']
                    session['role'] = 'mentor'
                    flash("Login successful!", "success")
                    return redirect(url_for('dashboard'))

            flash("Invalid User ID or password", "danger")

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
    # It's recommended to set EMAIL_USER and EMAIL_PASS as environment variables
    # Example: export EMAIL_USER="myemail@gmail.com"
    # Example: export EMAIL_PASS="your_gmail_app_password"
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
        flash("OTP sent to your email!", "info") # Flash message upon success
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

        # Store data in session temporarily
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
                send_otp(email, otp) # Call the send_otp function (flash message handled inside)
                return render_template('register_step1.html', show_otp=True)
        else: # Marwadi college, no OTP needed
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
            # Insert into users - use %s
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
                    'student', # role is hardcoded as 'student'
                    year,
                    branch,
                    department,
                    hashed_password
                )
            )
            conn.commit()

            # Set session variables for auto-login
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
            # Insert into mentors - use %s
            cur.execute('''INSERT INTO mentors 
                (user_id, name, college, email, expertise, skills, password)
                VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (user_id, name, college, email, expertise, skills, hashed_password)
            )
            conn.commit()

            # Set session variables for auto-login
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

    # Use DictCursor for fetching data here
    cur = conn.cursor(cursor_factory=DictCursor) 

    events_for_template = []
    rooms = []
    processed_results = defaultdict(list)

    try:
        # Get all events with full description and image path
        cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
        events_raw = cur.fetchall()

        for event_row in events_raw:
            event_id = event_row['id'] # Access by key
            event_data = {
                'id': event_id,
                'title': event_row['title'],
                'description': event_row['description'], # Full description
                'date': event_row['date'],
                'short_description': event_row['short_description'],
                'image_path': event_row['image_path'],
                'stages': [] # To store stage details
            }

            # Fetch stages for each event - use %s
            cur.execute("SELECT id, stage_title, deadline FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
            stages_for_event = cur.fetchall()
            for stage_row in stages_for_event: # Use stage_row for DictCursor
                event_data['stages'].append({
                    'id': stage_row['id'],
                    'stage_title': stage_row['stage_title'],
                    'deadline': stage_row['deadline']
                })
            events_for_template.append(event_data)


        # Get all brainstorm rooms
        cur.execute("SELECT room_id, title, created_by FROM brainstorm_rooms ORDER BY created_at DESC")
        rooms = cur.fetchall() # These are DictRows already

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
        raw_results = cur.fetchall() # These are DictRows already

        # Process raw_results into a dictionary format suitable for the template
        for result_row in raw_results: # Loop through DictRows
            event_title = result_row['event_title'] # Access by key
            position = result_row['position']
            winner_name = result_row['winner_name']
            processed_results[event_title].append([winner_name, position, ""]) # Added empty string for winner[2]

    except psycopg2.Error as e:
        flash(f"Database error on mentor dashboard: {e}", "danger")
        print(f"MENTOR DASHBOARD ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('mentor_dashboard.html',
                           events=events_for_template, # Pass the enriched events data
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
        # Loop for 3 positions
        for i in range(1, 4):
            position = request.form.get(f'position{i}')
            name = request.form.get(f'name{i}')
            email = request.form.get(f'email{i}')

            if name and email:  # only add if filled
                # Insert into event_results - use %s
                cur.execute('''
                    INSERT INTO event_results (event_title, position, winner_name, winner_email)
                    VALUES (%s, %s, %s, %s)
                ''', (event_title, position, name, email))

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

    # Use DictCursor for fetching event data
    cur = conn.cursor(cursor_factory=DictCursor)
    event = None
    already_registered = False

    try:
        # Fetch event info - use %s
        cur.execute("SELECT id, title, description, date, short_description, image_path FROM events WHERE id = %s", (event_id,))
        event = cur.fetchone() # This will be a DictRow

        # Check if student already registered - use %s
        cur.execute("SELECT id FROM event_registrations WHERE user_id = %s AND event_id = %s", 
                    (session['user_id'], event_id))
        already_registered = cur.fetchone() # Will be None if not registered, or a row if registered

        if request.method == 'POST' and not already_registered:
            # Insert into event_registrations - use %s
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

    # Use DictCursor for consistent data access
    cur = conn.cursor(cursor_factory=DictCursor)
    events_with_stages_and_submissions = []

    try:
        # Get all events the student is registered for - use %s
        cur.execute('''
            SELECT e.id, e.title, e.description, e.date, e.short_description, e.image_path
            FROM event_registrations r
            JOIN events e ON r.event_id = e.id
            WHERE r.user_id = %s
            ORDER BY e.date DESC
        ''', (session['user_id'],))

        registered_events_raw = cur.fetchall()

        for event_row in registered_events_raw:
            event_id = event_row['id'] # Access by key
            event_data = {
                'id': event_row['id'],
                'title': event_row['title'],
                'description': event_row['description'],
                'date': event_row['date'],
                'short_description': event_row['short_description'],
                'image_path': event_row['image_path'],
                'stages': [] # This will hold stage details including submission info
            }

            # Get all stages for the current event - use %s
            cur.execute("SELECT id, stage_title, deadline FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
            stages_for_event = cur.fetchall() # These are DictRows

            for stage_row in stages_for_event: # Loop through DictRows
                stage_id = stage_row['id'] # Access by key
                # Check for submission for this specific stage by the current user - use %s
                cur.execute('''
                    SELECT submission_text, submission_file, submitted_on
                    FROM submissions
                    WHERE user_id = %s AND event_id = %s AND stage_id = %s
                ''', (session['user_id'], event_id, stage_id))
                submission_info = cur.fetchone() # This will be a DictRow or None

                stage_details = {
                    'id': stage_id,
                    'stage_title': stage_row['stage_title'],
                    'deadline': stage_row['deadline'],
                    'submission_text': submission_info['submission_text'] if submission_info else None,
                    'submission_file': submission_info['submission_file'] if submission_info else None,
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

    # Use DictCursor for fetching event data
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        if request.method == 'POST':
            # Event Data
            title = request.form['title']
            description = request.form['description']
            date = request.form['date']
            short_desc = request.form['short_description']
            image_file = request.files.get('event_image')
            
            relative_path = None

            if image_file and image_file.filename and allowed_image(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_IMAGE_FOLDER'], filename)
                image_file.save(image_path)
                relative_path = os.path.join('uploads', filename) # For rendering in HTML (static/uploads/)
            
            # Insert new event - use %s and RETURNING id
            cur.execute('''INSERT INTO events (title, short_description, description, date, image_path)
                            VALUES (%s, %s, %s, %s, %s) RETURNING id''', 
                        (title, short_desc, description, date, relative_path))
            event_id = cur.fetchone()['id'] # Get the returned ID by key

            # Stage Data
            stages = request.form.getlist('stage_title[]')
            deadlines = request.form.getlist('deadline[]')

            for stage_title, deadline in zip(stages, deadlines):
                # Insert event stages - use %s
                cur.execute('INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)',
                            (event_id, stage_title, deadline))

            conn.commit()
            flash("Hackathon with stages created successfully!", "success")

        # Get all events for display
        cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
        events = cur.fetchall() # These are DictRows

        event_stats = []
        for event_row in events: # Loop through DictRows
            event_id = event_row['id'] # Access by key

            # Count registered students - use %s
            cur.execute("SELECT COUNT(*) FROM event_registrations WHERE event_id = %s", (event_id,))
            registered = cur.fetchone()[0]

            # Count submissions - use %s
            cur.execute("SELECT COUNT(*) FROM submissions WHERE event_id = %s", (event_id,))
            submitted = cur.fetchone()[0]

            event_stats.append({
                'event': event_row, # Pass the DictRow directly
                'registered': registered,
                'submitted': submitted
        })

    except psycopg2.Error as e:
        conn.rollback() # Ensure rollback on error
        flash(f"Database error on admin dashboard: {e}", "danger")
        print(f"ADMIN DASHBOARD ERROR: {e}")
        event_stats = [] # Ensure event_stats is defined even on error
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

    # Use DictCursor for consistent data access
    cur = conn.cursor(cursor_factory=DictCursor)
    progress = []
    stages = []

    try:
        # Get all stages (id and title) for this event - use %s
        cur.execute("SELECT id, stage_title FROM event_stages WHERE event_id = %s", (event_id,))
        stage_data = cur.fetchall() # These are DictRows

        if not stage_data:
            flash("No stages found for this event.", "warning")
            return redirect(url_for('admin_dashboard'))

        stages = [row['stage_title'] for row in stage_data]  # list of stage titles
        stage_id_map = {row['stage_title']: row['id'] for row in stage_data}  # title -> id

        # Get all registered users for this event - use %s
        cur.execute('''
            SELECT u.user_id, u.name, u.email, u.college, u.roll_no
            FROM event_registrations r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.event_id = %s
        ''', (event_id,))
        participants = cur.fetchall() # These are DictRows

        for user_row in participants: # Loop through DictRows
            user_id = user_row['user_id'] # Access by key
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

                # Select submission file - use %s
                cur.execute('''
                    SELECT submission_file FROM submissions 
                    WHERE event_id = %s AND user_id = %s AND stage_id = %s
                ''', (event_id, user_id, stage_id))
                result = cur.fetchone() # This will be a DictRow or None

                if result and result['submission_file']: # Access by key
                    file_path = result['submission_file']  # relative path
                    user_info['stage_status'][stage_title] = {
                        'status': '✔️', 
                        'file': file_path
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


# --- GENERAL DOWNLOAD ROUTE (needs definition of UPLOAD_FOLDER or re-purpose) ---
@app.route('/download/<path:filename>')
def download_file(filename):
    """Handles general file downloads (appears unused based on provided code).
    Requires app.config['UPLOAD_FOLDER'] to be set."""
    if 'user_id' not in session:
        flash("Login required", "danger")
        return redirect(url_for('login'))

    if 'UPLOAD_FOLDER' not in app.config:
        flash("Download folder 'UPLOAD_FOLDER' not configured in app.config.", "danger")
        abort(500) # Internal Server Error if configuration is missing

    safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.isfile(safe_path):
        abort(404)

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/brainstorm', methods=['GET', 'POST'])
def brainstorm():
    """Handles creation and listing of brainstorm rooms."""
    if 'user_id' not in session or session['role'] != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('brainstorm.html', rooms=[])

    # Use DictCursor for fetching rooms
    cur = conn.cursor(cursor_factory=DictCursor)
    rooms_data = []

    try:
        if request.method == 'POST':
            room_title = request.form['room_title']
            room_id = str(uuid.uuid4())[:8]  # short unique ID (8 chars)
            created_by = session['user_id']
            created_at = datetime.now() # psycopg2 handles datetime objects directly

            # Insert into brainstorm_rooms - use %s
            cur.execute('''
                INSERT INTO brainstorm_rooms (room_id, title, created_by, created_at)
                VALUES (%s, %s, %s, %s)
            ''', (room_id, room_title, created_by, created_at))

            conn.commit()
            flash("Room created! Share the invite link.", "success")
            return redirect(url_for('join_brainstorm_room', room_id=room_id))

        # Fetch all rooms
        cur.execute('SELECT room_id, title, created_at FROM brainstorm_rooms ORDER BY created_at DESC')
        rooms_data = cur.fetchall() # These are DictRows
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

    # Use DictCursor for fetching chat history and user details
    cur = conn.cursor(cursor_factory=DictCursor)
    chat_history = []
    creator_id = None
    admin_name = "Unknown"

    try:
        # Get chat messages - use %s
        cur.execute("SELECT username, message, timestamp FROM brainstorm_chats WHERE room_id = %s ORDER BY timestamp ASC", (room_id,))
        chat_history = cur.fetchall() # This will now be a list of DictRows, accessible by key

        # Get created_by user_id from brainstorm_rooms - use %s
        cur.execute("SELECT created_by FROM brainstorm_rooms WHERE room_id = %s", (room_id,))
        creator_result = cur.fetchone() # This will be a DictRow or None
        creator_id = creator_result['created_by'] if creator_result else None # Access by key

        # Convert creator user_id to username - use %s
        if creator_id:
            cur.execute("SELECT name FROM users WHERE user_id = %s", (creator_id,))
            admin_result = cur.fetchone() # This will be a DictRow or None
            if admin_result:
                admin_name = admin_result['name'] # Access by key
            else: # If not in users, check mentors table - use %s
                cur.execute("SELECT name FROM mentors WHERE user_id = %s", (creator_id,))
                mentor_admin_result = cur.fetchone() # This will be a DictRow or None
                if mentor_admin_result:
                    admin_name = mentor_admin_result['name'] # Access by key

    except psycopg2.Error as e:
        flash(f"Database error in brainstorm room: {e}", "danger")
        print(f"BRAINSTORM ROOM ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    # shared_files is still in-memory and will reset on server restart.
    # For persistence, these files' metadata (filename, url, user, timestamp) should be stored in DB.
    # The `user` and `timestamp` keys are now added in `upload_file_brainstorm`.
    files = shared_files.get(room_id, []) 

    return render_template('brainstorm_room.html',
                           room_id=room_id,
                           user=user,
                           shared_files=files, # This will be an empty list on fresh load
                           chat_history=chat_history, # This will populate from DB
                           admin_name=admin_name)

@app.route('/student_dashboard')
def student_dashboard():
    """Renders the student dashboard with personal info, events, and results."""
    if 'user' not in session or session.get('role') != 'student':
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        return render_template('student_dashboard.html', student=None, events=[], results={})

    cur = conn.cursor(cursor_factory=DictCursor) # Use DictCursor for student and results
    student = None
    events = []
    grouped_results = {}

    try:
        # Get student info - use %s
        cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department FROM users WHERE user_id = %s", (session['user_id'],))
        student = cur.fetchone() # This will be a DictRow

        # Get all events
        cur.execute("SELECT id, title, description, date, short_description, image_path FROM events ORDER BY date DESC")
        events = cur.fetchall() # These are DictRows

        # Get winner results grouped by event
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
        raw_results = cur.fetchall() # These are DictRows

        # Group winners by event
        for result_row in raw_results: # Loop through DictRows
            event_title = result_row['event_title'] # Access by key
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
        if cur: cur.close()
        if conn: conn.close()

    return render_template('student_dashboard.html', student=student, events=events, results=grouped_results, role=session.get('role'))


@app.route('/brainstorm/upload/<room>', methods=['POST'])
def upload_file_brainstorm(room):
    """Handles file uploads to brainstorm rooms. Stores metadata in-memory."""
    file = request.files['file']
    # Get the user who shared the file from the form data (sent by JS)
    user_who_uploaded = request.form.get('user') # This `user` is the username
    
    if file and user_who_uploaded:
        filename = secure_filename(file.filename)
        save_path = os.path.join(BRAINSTORM_FOLDER, filename)
        try:
            file.save(save_path)

            # Use the RENAMED route for brainstorm file downloads
            file_url = url_for('download_brainstorm_file', filename=filename) 

            # Save to shared_files (in-memory for now - ADD USER AND TIMESTAMP)
            if room not in shared_files:
                shared_files[room] = []
            
            # Store full metadata needed for client-side display
            shared_files[room].append({
                'filename': filename,
                'url': file_url,
                'user': user_who_uploaded, # Store the username
                'timestamp': datetime.now().isoformat() # Store ISO formatted timestamp
            })

            return jsonify(status='success', filename=filename, file_url=file_url, user=user_who_uploaded, timestamp=datetime.now().isoformat())
        except Exception as e:
            print(f"File upload error: {e}")
            return jsonify(status='error', message=f"Failed to save file: {e}")
    return jsonify(status='error', message="No file or user provided for upload.")

@app.route('/brainstorm/files/<room>')
def get_shared_files(room):
    """Returns a JSON list of files shared in a brainstorm room (from in-memory store).
    Includes user and timestamp for each file."""
    # This currently serves the in-memory shared_files dictionary
    files = shared_files.get(room, [])
    return jsonify(files)

@app.route('/brainstorm/create', methods=['POST'])
def create_room():
    """Handles creating a new brainstorm room.
    Note: This route seems to duplicate logic with /brainstorm's POST handling.
    Consider consolidating."""
    room_id = str(uuid.uuid4())[:8] # Consistent 8-char ID
    admin_name = session.get('user', 'Guest')
    # rooms is an in-memory dictionary, for real rooms, this should be consistent with DB.
    rooms[room_id] = {'admin': admin_name, 'chat': [], 'files': []} 
    flash(f"Room created! Share the invite link: /brainstorm/room/{room_id}", "success")
    return redirect(url_for('join_brainstorm_room', room_id=room_id))

@socketio.on('join')
def handle_join(data):
    """Handles a user joining a SocketIO room."""
    room = data.get('room')
    user = data.get('user', 'Anonymous')
    if room and user:
        join_room(room)
        # Emit to the room that a user joined, include current timestamp
        emit('message', {'user': 'System', 'msg': f"{user} joined the room.", 'timestamp': datetime.now().isoformat()}, to=room)
    else:
        print("Invalid data for join event:", data)


@socketio.on('send_message')
def handle_message(data):
    """Handles sending and saving chat messages in a brainstorm room."""
    room = data.get('room')
    user = data.get('user')
    msg = data.get('msg')
    timestamp = data.get('timestamp') # Client is now sending timestamp

    if not all([room, user, msg]):
        print("Invalid message data:", data)
        return

    # Save to DB
    conn = get_db_connection()
    if conn is None:
        return # Cannot save message if DB connection fails
    
    cur = conn.cursor()
    try:
        # Insert into brainstorm_chats - use %s
        # Convert ISO timestamp string back to datetime object for DB storage
        db_timestamp = datetime.fromisoformat(timestamp) if timestamp else datetime.now()
        cur.execute("INSERT INTO brainstorm_chats (room_id, username, message, timestamp) VALUES (%s, %s, %s, %s)", 
                    (room, user, msg, db_timestamp))
        conn.commit()
        # Emit with user, message, AND timestamp for other clients
        emit('message', {'user': user, 'msg': msg, 'timestamp': timestamp}, to=room)
    except psycopg2.Error as e:
        conn.rollback()
        print(f"CHAT MESSAGE SAVE ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

@socketio.on('share_file') # NEW Socket.IO event handler for file sharing
def handle_share_file(data):
    """Handles real-time notification of a file being shared in a brainstorm room."""
    room = data.get('room')
    user = data.get('user')
    filename = data.get('filename')
    file_url = data.get('file_url')
    timestamp = data.get('timestamp') # Client is sending timestamp

    if not all([room, user, filename, file_url, timestamp]):
        print("Invalid file share data:", data)
        return
    
    # At this point, the file is already saved to disk and metadata is in `shared_files` (in-memory)
    # If you wanted to store file metadata persistently in DB, this would be the place to do it.
    
    # Emit the file details to all clients in the room
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
        session.clear() # Clear session if user data is missing
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Update profile information
        contact = request.form.get('contact')
        address = request.form.get('address')
        year = request.form.get('year')
        branch = request.form.get('branch')
        department = request.form.get('department')

        conn = get_db_connection()
        if conn is None:
            return render_template('profile.html', user_data=user_data) # Keep current data

        cur = conn.cursor()
        try:
            # Update users table - use %s
            cur.execute('''
                UPDATE users
                SET contact = %s, address = %s, year = %s, branch = %s, department = %s
                WHERE user_id = %s
            ''', (contact, address, year, branch, department, session['user_id']))
            conn.commit()
            flash("Profile updated successfully!", "success")
            # Re-fetch user data to update the displayed info immediately
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

    if not check_password_hash(user_data['password'], current_password): # Access by key if DictCursor
        flash("Current password incorrect.", "danger")
        return redirect(url_for('profile'))

    if new_password != confirm_new_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))

    if len(new_password) < 6: # Basic password length validation
        flash("New password must be at least 6 characters long.", "danger")
        return redirect(url_for('profile'))

    hashed_new_password = generate_password_hash(new_password)

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('profile'))

    cur = conn.cursor()
    try:
        # Update users password - use %s
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
    # You can define UPLOAD_FOLDER here if the /download/<path:filename> route is intended for general use.
    # For example:
    # app.config['UPLOAD_FOLDER'] = 'general_uploads'
    # if not os.path.exists('general_uploads'): os.makedirs('general_uploads')
    socketio.run(app, debug=True)
