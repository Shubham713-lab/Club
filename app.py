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

# Ensure these environment variables are set in your deployment environment
DATABASE_URL = os.getenv("DATABASE_URL")
EMAIL_ADDRESS = os.environ.get("EMAIL_USER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        print("[CONFIG ERROR] DATABASE_URL environment variable not set.")
        flash("Database configuration error: Please contact support.", "danger")
        return None
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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_default_key_replace_me') # Changed default for security

# Cloudinary Configuration
cloudinary.config(
    cloud_name = os.environ.get('CLOUD_NAME'),
    api_key = os.environ.get('API_KEY'),
    api_secret = os.environ.get('API_SECRET')
)
if not all([os.environ.get('CLOUD_NAME'), os.environ.get('API_KEY'), os.environ.get('API_SECRET')]):
    print("[CONFIG ERROR] Cloudinary credentials not fully set in environment variables.")

# Allowed extensions for submissions and images (still good for client-side validation)
ALLOWED_SUBMISSION_EXTENSIONS = {'pdf', 'ppt', 'pptx', 'doc', 'docx'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def get_user_by_id(user_id):
    """Fetches user data by user_id from the 'users' table."""
    conn = get_db_connection()
    if conn is None:
        return None
    
    cur = conn.cursor(cursor_factory=DictCursor)
    user_data = None
    try:
        cur.execute("SELECT user_id, name, college, roll_no, email, address, contact, role, year, branch, department, password FROM users WHERE user_id = %s", (user_id,))
        user_data = cur.fetchone()
        if user_data:
            return dict(user_data) # Convert DictRow to a standard dictionary
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

    cur = conn.cursor(cursor_factory=DictCursor) # Use DictCursor for fetching stage details
    stage_title = None
    deadline = None

    try:
        cur.execute("SELECT stage_title, deadline FROM event_stages WHERE id = %s", (stage_id,))
        stage = cur.fetchone()
        if not stage:
            flash("Invalid stage", "danger")
            return redirect(url_for('student_registered_events'))

        stage_title = stage['stage_title']
        deadline = stage['deadline']

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
            if file and file.filename:
                if allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder="submissions") 
                        submission_file_url = upload_result['secure_url']
                    except Exception as e:
                        flash(f"Submission file upload failed: {e}", "danger")
                        print(f"CLOUDINARY SUBMISSION UPLOAD ERROR: {e}")
                        # If upload fails, allow text submission if available, but warn about file
                else:
                    flash("Invalid file type. Only PDF, PPT, PPTX, DOC, DOCX allowed.", "danger")
                    # Still render the template with correct stage info if file type is wrong
                    return render_template('submit_stage.html', stage={'stage_title': stage_title, 'deadline': deadline}, event_id=event_id, stage_id=stage_id)


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
    
    # Pass stage as a dictionary for template consistency
    return render_template('submit_stage.html', stage={'stage_title': stage_title, 'deadline': deadline}, event_id=event_id, stage_id=stage_id)


# ---------- Home Page ----------
@app.route('/')
def home():
    """Renders the home page with a list of events."""
    conn = get_db_connection()
    if conn is None:
        return render_template('home.html', events=[], results={}) # Pass empty results too

    cur = conn.cursor(cursor_factory=DictCursor)
    events_data = []
    processed_results = defaultdict(list)
    try:
        # Select image_url from events table
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events_data = cur.fetchall()

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
        raw_results = cur.fetchall()

        for result_row in raw_results:
            event_title = result_row['event_title']
            position = result_row['position']
            name = result_row['winner_name']
            email = result_row['winner_email']
            if event_title not in processed_results:
                processed_results[event_title] = []
            # Ensure the structure matches what the template expects: [name, position, email]
            processed_results[event_title].append([name, position, email])

    except psycopg2.Error as e:
        flash(f"Error loading events or results for home page: {e}", "danger")
        print(f"HOME PAGE DATA ERROR: {e}")
        events_data = []
        processed_results = {}
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    # Convert DictRows to dictionaries for the template
    events_for_template = [dict(event) for event in events_data]
    return render_template('home.html', events=events_for_template, results=dict(processed_results))

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login for admins, students, and mentors."""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')

        conn = get_db_connection()
        if conn is None:
            flash("Database connection failed. Please try again later.", "danger")
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
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("[CONFIG ERROR] Email credentials not set in environment variables (EMAIL_USER, EMAIL_PASS).")
        flash("Email sending failed: Server not configured. Contact admin.", "danger")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'OTP Verification - Code Forge' # Changed club name
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = receiver_email
    msg.set_content(f'Your OTP is: {otp}\n\nThis OTP is valid for 10 minutes.\nDo not share it with anyone.')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[SUCCESS] OTP sent to {receiver_email}")
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
    all_students = []
    all_mentors = []

    try:
        cur.execute("SELECT user_id, name, college, email, role, contact FROM users ORDER BY name ASC")
        all_students = cur.fetchall() # Fetches DictRows

        cur.execute("SELECT user_id, name, college, email, expertise FROM mentors ORDER BY name ASC")
        all_mentors = cur.fetchall() # Fetches DictRows

        # Convert DictRows to plain dictionaries for safety/flexibility if needed by template
        all_students = [dict(s) for s in all_students]
        all_mentors = [dict(m) for m in all_mentors]

    except psycopg2.Error as e:
        flash(f"Database error fetching users: {e}", "danger")
        print(f"VIEW ALL USERS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('view_all_users.html', users=all_students, mentors=all_mentors)


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

    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        # Get event title and image_url to potentially delete from Cloudinary if desired
        cur.execute("SELECT title, image_url FROM events WHERE id = %s", (event_id,))
        event_info = cur.fetchone()
        
        # NOTE: Cloudinary deletion
        # If you want to delete the image from Cloudinary when the event is deleted,
        # you would add code here. Example:
        # if event_info and event_info['image_url']:
        #     public_id = event_info['image_url'].split('/')[-1].split('.')[0] # Extract public_id
        #     cloudinary.uploader.destroy(f"event_images/{public_id}") # Assuming 'event_images' folder

        # Delete event results (linked by event_title)
        if event_info:
            cur.execute("DELETE FROM event_results WHERE event_title = %s", (event_info['title'],))
        
        # Delete the event itself (PostgreSQL cascade will handle stages, registrations, submissions)
        cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
        
        conn.commit()
        flash("Event and all associated data deleted successfully!", "success")

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error deleting event: {e}", "danger")
        print(f"DELETE EVENT ERROR: {e}")
    except Exception as e:
        conn.rollback() # Ensure rollback on general errors too
        flash(f"An unexpected error occurred during event deletion: {e}", "danger")
        print(f"UNEXPECTED DELETE EVENT ERROR: {e}")
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

        # Store in session temporarily
        session['name'] = name
        session['college'] = college
        session['roll_no'] = roll_no
        session['email'] = email

        if "marwadi" not in college.lower():
            if otp_input: # User submitted OTP
                if otp_input == session.get('otp'):
                    flash("OTP Verified", "success")
                    return redirect(url_for('register_details'))
                else:
                    flash("Invalid OTP", "danger")
                    return render_template('register_step1.html', show_otp=True)
            else: # User requested OTP
                otp = str(random.randint(100000, 999999))
                session['otp'] = otp
                if send_otp(email, otp): # Only flash if email sending was successful
                    pass # send_otp already flashes success/info
                return render_template('register_step1.html', show_otp=True)
        else: # If college is Marwadi, no OTP needed, proceed
            return redirect(url_for('register_details'))

    return render_template('register_step1.html', show_otp=False)

# ---------- Student Registration Step 2 ----------
@app.route('/register_details', methods=['GET', 'POST'])
def register_details():
    """Handles the second step of student registration (collects detailed info and saves to DB)."""
    # Ensure session data exists from step 1
    if 'name' not in session or 'email' not in session:
        flash("Please complete the first step of registration.", "danger")
        return redirect(url_for('register_student'))

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

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
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
                    'student', # role is 'student'
                    year,
                    branch,
                    department,
                    hashed_password
                )
            )
            conn.commit()

            # Clear temporary registration data from session
            session.pop('name', None)
            session.pop('college', None)
            session.pop('roll_no', None)
            session.pop('email', None)
            session.pop('otp', None) # Clear OTP after successful registration

            session['user'] = session['name'] # This will be the name from registration
            session['user_id'] = user_id
            session['role'] = 'student'
            flash(f"Student Registration complete! Your User ID is {user_id}", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            # Check for unique constraint violation (e.g., duplicate email/roll_no if unique)
            if 'unique' in str(e).lower():
                flash("A user with this email or roll number already exists.", "danger")
            else:
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

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
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

            session['user'] = name
            session['user_id'] = user_id
            session['role'] = 'mentor'
            flash(f"Mentor Registration complete! Your User ID is {user_id}", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            if 'unique' in str(e).lower():
                flash("A mentor with this email already exists.", "danger")
            else:
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
    flash("Please log in to access the dashboard.", "info")
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
            # Convert DictRow to a plain dictionary for cleaner access in template (optional, but good practice)
            event_data = dict(event_row) 
            event_data['stages'] = [] # Initialize stages list

            cur.execute("SELECT id, stage_title, deadline FROM event_stages WHERE event_id = %s ORDER BY deadline ASC", (event_id,))
            stages_for_event = cur.fetchall()
            for stage_row in stages_for_event:
                event_data['stages'].append(dict(stage_row)) # Convert DictRow to dict
            events_for_template.append(event_data)

        # Get all brainstorm rooms
        cur.execute("SELECT room_id, title, created_at FROM brainstorm_rooms ORDER BY created_at DESC")
        rooms = [dict(r) for r in cur.fetchall()] # Convert to list of dicts

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
            processed_results[event_title].append([winner_name, position, ""]) # No email in this query, pass empty string

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
    if not event_title:
        flash("Event title is required to announce winners.", "danger")
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    if conn is None:
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor()

    try:
        # It's good practice to clear previous winners for this event before inserting new ones
        cur.execute("DELETE FROM event_results WHERE event_title = %s", (event_title,))

        found_winner = False
        for i in range(1, 4):
            position = request.form.get(f'position{i}')
            name = request.form.get(f'name{i}')
            email = request.form.get(f'email{i}')

            if name and position: # Email is optional based on your form/schema
                cur.execute('''
                    INSERT INTO event_results (event_title, position, winner_name, winner_email)
                    VALUES (%s, %s, %s, %s)
                ''', (event_title, position, name, email))
                found_winner = True
        
        if not found_winner:
            flash("No winners were entered. Please fill in at least one winner's name and position.", "warning")
            conn.rollback() # Rollback the delete if no new winners were added
            return redirect(url_for('admin_dashboard'))


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
    # This route can be accessed by non-logged in users or other roles to view details
    # but registration requires student role.
    user_is_student = ('user_id' in session and session.get('role') == 'student')

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Please try again later.", "danger")
        return render_template('event_detail.html', event=None, registered=False)

    cur = conn.cursor(cursor_factory=DictCursor)
    event = None
    already_registered = False

    try:
        # Fetch event info - select image_url
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events WHERE id = %s", (event_id,))
        event = cur.fetchone()
        if event:
            event = dict(event) # Convert to dictionary

        if user_is_student: # Only check registration status if user is a student
            cur.execute("SELECT id FROM event_registrations WHERE user_id = %s AND event_id = %s", 
                        (session['user_id'], event_id))
            already_registered = cur.fetchone() is not None # Check if any row was returned

        if request.method == 'POST':
            if not user_is_student:
                flash("Please log in as a student to register for events.", "danger")
                return redirect(url_for('login'))
            
            if already_registered:
                flash("You are already registered for this event.", "info")
                # No redirect here, keep on the page, or redirect to registered events
                return render_template('event_detail.html', event=event, registered=already_registered)


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
        return render_template('registered_events.html', events=[], stages={})

    cur = conn.cursor(cursor_factory=DictCursor)
    events_for_template = []

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
            event_data = dict(event_row) # Convert DictRow to dictionary
            event_data['stages'] = [] # Initialize stages list

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

            events_for_template.append(event_data)

    except psycopg2.Error as e:
        flash(f"Database error fetching registered events: {e}", "danger")
        print(f"REGISTERED EVENTS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    # The template expects 'events' to be a list of events, each containing its stages
    # It also expects 'stages' as a separate dict. I'll modify the template later if needed.
    # For now, events_for_template already contains stages nested within it.
    # Let's match the old structure if your template relies on it:
    # `stages` will be a dictionary where keys are event_id and values are list of stages
    stages_dict_for_template = {}
    for event in events_for_template:
        stages_dict_for_template[event['id']] = event['stages'] # Extract stages for the separate dict

    return render_template('registered_events.html', events=events_for_template, stages=stages_dict_for_template)


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
            if image_file and image_file.filename:
                if allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
                    try:
                        upload_result = cloudinary.uploader.upload(image_file, folder="event_images") 
                        image_url = upload_result['secure_url']
                    except Exception as e:
                        flash(f"Event image upload failed: {e}", "danger")
                        print(f"CLOUDINARY EVENT IMAGE UPLOAD ERROR: {e}")
                else:
                    flash("Invalid image file type. Only PNG, JPG, JPEG, GIF, WEBP allowed.", "danger")
                    # Allow form to be rendered again with error without losing input (if you were to re-render form)
                    # For now, just flash and continue with null image_url

            # Insert new event - use image_url column
            cur.execute('''INSERT INTO events (title, short_description, description, date, image_url)
                            VALUES (%s, %s, %s, %s, %s) RETURNING id''', # RETURNING id is useful for stages
                        (title, short_desc, description, date, image_url))
            event_id = cur.fetchone()['id'] # Get the newly inserted event's ID

            stages = request.form.getlist('stage_title[]')
            deadlines = request.form.getlist('deadline[]')

            if stages and deadlines and len(stages) == len(deadlines):
                for stage_title, deadline in zip(stages, deadlines):
                    if stage_title and deadline: # Only insert if both are provided
                        cur.execute('INSERT INTO event_stages (event_id, stage_title, deadline) VALUES (%s, %s, %s)',
                                    (event_id, stage_title, deadline))
            else:
                flash("No stages provided or mismatch in stage titles/deadlines.", "warning")

            conn.commit()
            flash("Event with stages created successfully!", "success")

        # Get all events for display - select image_url
        cur.execute("SELECT id, title, description, date, short_description, image_url FROM events ORDER BY date DESC")
        events = cur.fetchall()

        event_stats = []
        for event_row in events:
            event_id = event_row['id']
            event_data = dict(event_row) # Convert to dictionary

            cur.execute("SELECT COUNT(*) FROM event_registrations WHERE event_id = %s", (event_id,))
            registered = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM submissions WHERE event_id = %s", (event_id,))
            submitted = cur.fetchone()[0]

            event_stats.append({
                'event': event_data, # Pass event as a dictionary
                'registered': registered,
                'submitted': submitted
            })

    except psycopg2.Error as e:
        conn.rollback()
        flash(f"Database error on admin dashboard: {e}", "danger")
        print(f"ADMIN DASHBOARD ERROR: {e}")
        event_stats = []
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
        flash("Database connection failed. Cannot view progress.", "danger")
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=DictCursor)
    progress = []
    stages_list = [] # Renamed to avoid conflict with `stages` map

    try:
        cur.execute("SELECT id, stage_title FROM event_stages WHERE event_id = %s ORDER BY id ASC", (event_id,))
        stage_data = cur.fetchall()

        if not stage_data:
            flash("No stages found for this event.", "warning")
            return redirect(url_for('admin_dashboard'))

        stages_list = [row['stage_title'] for row in stage_data] # list of stage titles
        stage_id_map = {row['stage_title']: row['id'] for row in stage_data} # title -> id

        cur.execute('''
            SELECT u.user_id, u.name, u.email, u.college, u.roll_no
            FROM event_registrations r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.event_id = %s
            ORDER BY u.name ASC
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

            for stage_title in stages_list:
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
                        'status': '✅', # Indicate completion
                        'file': file_url # This is now a URL
                    }
                else:
                    user_info['stage_status'][stage_title] = {
                        'status': '❌', # Indicate not submitted
                        'file': None
                    }

            progress.append(user_info)

    except psycopg2.Error as e:
        flash(f"Database error viewing progress: {e}", "danger")
        print(f"VIEW PROGRESS ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    return render_template('view_progress.html', progress=progress, stages=stages_list, event_id=event_id)


# Brainstorming Related Routes
@app.route('/brainstorm', methods=['GET', 'POST'])
def brainstorm():
    """Handles creation and listing of brainstorm rooms."""
    if 'user_id' not in session or session['role'] not in ['student', 'mentor']:
        flash("Unauthorized access", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Please contact support.", "danger")
        return render_template('brainstorm.html', rooms=[])

    cur = conn.cursor(cursor_factory=DictCursor)
    rooms_data = []

    try:
        if request.method == 'POST':
            room_title = request.form['room_title']
            if not room_title:
                flash("Room title cannot be empty.", "danger")
                return redirect(url_for('brainstorm')) # Redirect back to display existing rooms

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

        cur.execute('SELECT room_id, title, created_at FROM brainstorm_rooms ORDER BY created_at DESC')
        rooms_data = [dict(r) for r in cur.fetchall()] # Convert DictRows to dicts
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

    user_name = session.get("user") # Use 'user' for display name, 'user_id' for DB ops
    user_role = session.get("role")

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed. Please try again later.", "danger")
        return render_template('brainstorm_room.html', room_id=room_id, user=user_name, shared_files=[], chat_history=[], admin_name="Database Error", role=user_role)

    cur = conn.cursor(cursor_factory=DictCursor)
    chat_history = []
    shared_files_data = []
    creator_id = None
    admin_name = "Unknown"

    try:
        cur.execute("SELECT username, message, timestamp FROM brainstorm_chats WHERE room_id = %s ORDER BY timestamp ASC", (room_id,))
        chat_history = [dict(c) for c in cur.fetchall()]

        cur.execute("SELECT filename, file_url, uploaded_by_user, uploaded_at FROM brainstorm_room_files WHERE room_id = %s ORDER BY uploaded_at ASC", (room_id,))
        shared_files_data = [dict(f) for f in cur.fetchall()]

        cur.execute("SELECT created_by FROM brainstorm_rooms WHERE room_id = %s", (room_id,))
        creator_result = cur.fetchone()
        creator_id = creator_result['created_by'] if creator_result else None

        if creator_id:
            # Try to get creator name from users table (students)
            cur.execute("SELECT name FROM users WHERE user_id = %s", (creator_id,))
            creator_name_row = cur.fetchone()
            if creator_name_row:
                admin_name = creator_name_row['name']
            else: # Try to get creator name from mentors table
                cur.execute("SELECT name FROM mentors WHERE user_id = %s", (creator_id,))
                creator_name_row = cur.fetchone()
                if creator_name_row:
                    admin_name = creator_name_row['name']

    except psycopg2.Error as e:
        flash(f"Database error in brainstorm room: {e}", "danger")
        print(f"BRAINSTORM ROOM ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

    return render_template('brainstorm_room.html',
                           room_id=room_id,
                           user=user_name,
                           shared_files=shared_files_data,
                           chat_history=chat_history,
                           admin_name=admin_name,
                           role=user_role)


@app.route('/brainstorm/upload/<room>', methods=['POST'])
def upload_file_brainstorm(room):
    """Handles file uploads to brainstorm rooms. Persists metadata to PostgreSQL and file to Cloudinary."""
    if 'user_id' not in session:
        return jsonify(status='error', message="Unauthorized. Please log in to upload files."), 403

    file = request.files.get('file') # Use .get() for safety
    user_who_uploaded = session.get('user') # Get current user's display name from session
    
    if not file or not user_who_uploaded:
        return jsonify(status='error', message="No file or user provided for upload."), 400

    if not allowed_file(file.filename, ALLOWED_SUBMISSION_EXTENSIONS):
        return jsonify(status='error', message="Invalid file type. Only PDF, PPT, PPTX, DOC, DOCX allowed."), 400

    try:
        upload_result = cloudinary.uploader.upload(file, resource_type="raw", folder=f"brainstorm_rooms/{room}") 
        file_url = upload_result['secure_url']
        filename = secure_filename(file.filename) # Sanitize filename for display/storage

        conn = get_db_connection()
        if conn is None:
            return jsonify(status='error', message="Database connection failed for file persistence."), 500
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO brainstorm_room_files (room_id, filename, file_url, uploaded_by_user, uploaded_at)
                VALUES (%s, %s, %s, %s, %s)
            ''', (room, filename, file_url, user_who_uploaded, datetime.now()))
            conn.commit()
        except psycopg2.Error as e:
            conn.rollback()
            print(f"DATABASE ERROR SAVING BRAINSTORM FILE METADATA: {e}")
            return jsonify(status='error', message=f"Failed to save file metadata to DB: {e}"), 500
        finally:
            if cur: cur.close()
            if conn: conn.close()

        # Emit to all users in the room that a file has been shared
        # Ensure timestamp is ISO format for consistent parsing in JS
        timestamp_iso = datetime.now().isoformat()
        socketio.emit('file_shared', {
            'user': user_who_uploaded,
            'filename': filename,
            'file_url': file_url,
            'timestamp': timestamp_iso
        }, to=room)

        return jsonify(status='success', filename=filename, file_url=file_url, user=user_who_uploaded, timestamp=timestamp_iso), 200
    except Exception as e:
        print(f"Cloudinary file upload error: {e}")
        return jsonify(status='error', message=f"Failed to upload file: {e}"), 500


@app.route('/brainstorm/files/<room>')
def get_shared_files(room):
    """Returns a JSON list of files shared in a brainstorm room (from DB)."""
    conn = get_db_connection()
    if conn is None:
        return jsonify(status='error', message="Database connection failed to fetch files."), 500
    cur = conn.cursor(cursor_factory=DictCursor)
    files_data = []
    try:
        cur.execute("SELECT filename, file_url, uploaded_by_user, uploaded_at FROM brainstorm_room_files WHERE room_id = %s ORDER BY uploaded_at ASC", (room,))
        files_data = [dict(row) for row in cur.fetchall()] # Convert DictRows to plain dictionaries
    except psycopg2.Error as e:
        print(f"DATABASE ERROR FETCHING BRAINSTORM FILES: {e}")
        return jsonify(status='error', message=f"Failed to fetch files from DB: {e}"), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    return jsonify(files_data), 200

# This route is a bit redundant with the POST logic in /brainstorm, consider consolidating.
# Kept for now to match original structure, but POST to /brainstorm handles room creation
@app.route('/brainstorm/create', methods=['POST'])
def create_room_legacy(): # Renamed to avoid confusion
    """Handles creating a new brainstorm room (legacy route, use /brainstorm POST instead)."""
    if 'user_id' not in session or session['role'] not in ['student', 'mentor']:
        flash("Unauthorized access to create room", "danger")
        return redirect(url_for('dashboard'))

    # This route logic is mostly duplicated in /brainstorm (POST)
    # Consider removing this route and ensuring all room creation goes through /brainstorm (POST)
    flash("Please use the 'Create Room' form on the Brainstorming Ideas page.", "info")
    return redirect(url_for('brainstorm'))


@socketio.on('join')
def handle_join(data):
    """Handles a user joining a SocketIO room."""
    room = data.get('room')
    user = data.get('user', 'Anonymous')
    if room and user:
        join_room(room)
        # Emit to all including sender, then specifically to new joiner (or just all)
        emit('message', {'user': 'System', 'msg': f"{user} joined the room.", 'timestamp': datetime.now().isoformat()}, to=room)
    else:
        print("Invalid data for join event:", data)


@socketio.on('send_message')
def handle_message(data):
    """Handles sending and saving chat messages in a brainstorm room."""
    room = data.get('room')
    user = data.get('user')
    msg = data.get('msg')
    # Timestamp is now sent from client-side JS, or default to server time
    timestamp_str = data.get('timestamp') 

    if not all([room, user, msg]):
        print("Invalid message data:", data)
        return

    conn = get_db_connection()
    if conn is None:
        return
    
    cur = conn.cursor()
    try:
        # Convert ISO format string to datetime object
        db_timestamp = datetime.fromisoformat(timestamp_str) if timestamp_str else datetime.now()
        cur.execute("INSERT INTO brainstorm_chats (room_id, username, message, timestamp) VALUES (%s, %s, %s, %s)", 
                    (room, user, msg, db_timestamp))
        conn.commit()
        # Emit back the same timestamp for consistency
        emit('message', {'user': user, 'msg': msg, 'timestamp': timestamp_str}, to=room)
    except psycopg2.Error as e:
        conn.rollback()
        print(f"CHAT MESSAGE SAVE ERROR: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()

@socketio.on('disconnect')
def test_disconnect():
    print("Client disconnected")


# Removed the now-redundant download_submission route, as files are served directly from Cloudinary URLs


# ---------- Logout ----------
@app.route('/logout')
def logout():
    """Logs out the current user and clears the session."""
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# ---------- Run App ----------
if __name__ == '__main__':
    # Ensure environment variables are set before running
    if not DATABASE_URL:
        print("FATAL: DATABASE_URL environment variable is not set. Exiting.")
        exit(1)
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("WARNING: EMAIL_USER or EMAIL_PASS environment variables are not set. Email functionality may not work.")
    if not all([os.environ.get('CLOUD_NAME'), os.environ.get('API_KEY'), os.environ.get('API_SECRET')]):
        print("WARNING: Cloudinary credentials not fully set. File uploads may not work.")

    socketio.run(app, debug=True)