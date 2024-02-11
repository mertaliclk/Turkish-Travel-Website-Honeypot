from flask import Flask, request, render_template, session, redirect, url_for, send_file,flash
import sqlite3
import hashlib
import random
import datetime
from flask_mail import Mail, Message
from captcha.image import ImageCaptcha
import io
import string,feedparser, logging
from logging.handlers import RotatingFileHandler
from twilio.rest import Client

app = Flask(__name__)
app.secret_key = 'a_random_secret_key'  # Replace with a strong secret key in production
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # or 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = '' #fill this part with your details
app.config['MAIL_PASSWORD'] = '' #fill this part with your details
app.config['MAIL_DEFAULT_SENDER'] = '' #fill this part with your details


#twilio details
twilio_account_sid = ''#fill this part with your details
twilio_auth_token = ''#fill this part with your details
twilio_phone_number = ''#fill this part with your details
my_phone_number = ''#fill this part with your details

# Initialize Twilio client
twilio_client = Client(twilio_account_sid, twilio_auth_token)

# Function to send SMS via Twilio
def send_sms_via_twilio(to_number, body):
    try:
        message = twilio_client.messages.create(
            body=body,
            to=to_number,
            from_=twilio_phone_number
        )
        return message.sid
    except Exception as e:
        print(f"Failed to send SMS: {e}")
        return None


logger = logging.getLogger('honeypot_logger')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('honeypot.log', maxBytes=10000000, backupCount=5)
logger.addHandler(handler)

def log_request(req_type, endpoint, status, remote_addr, user_agent):
    # Classify the attempt type based on the endpoint and status
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attempt_type = "Normal Request"
    if endpoint == "/verify_reset_code" and "Invalid reset code." in status:
        attempt_type = "Password Reset Abuse"
    elif endpoint == "/login" and "Failed" in status:
        attempt_type = "Login Attempt"
    elif endpoint == "/admin_login" and "Failed" in status:
        attempt_type = "Admin Login Attempt"
    elif endpoint == "/verify_mfa" and "Failed" in status:
        attempt_type = "MFA Verification Abuse"

    # Log the detailed request information without email
    logger.info(f"Time: {current_time}, RequestType: {req_type}, Endpoint: {endpoint}, Status: {status}, "
                f"IP: {remote_addr}, UserAgent: {user_agent}, "
                f"AttemptType: {attempt_type}")

mail = Mail(app)
admin_mfa_codes = {}
reset_codes = {}
comments = {}  # In-memory storage for comments
admin_attempt_counters = {}

@app.route('/captcha')
def captcha():
    image = ImageCaptcha(width=280, height=90)
    # Generate a random alphanumeric string for captcha_text
    characters = string.ascii_letters + string.digits
    captcha_text = ''.join(random.choice(characters) for i in range(6))  # e.g., "x5ash21"
    data = image.generate(captcha_text)
    session['captcha_answer'] = captcha_text.lower()  # Store lowercase version for case-insensitive comparison
    return send_file(io.BytesIO(data.read()), mimetype='image/png')

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def send_reset_email(email, reset_code):
    try:
        msg = Message('Password Reset Code', sender='no-reply@example.com', recipients=[email])
        msg.body = f'Your password reset code is: {reset_code}\tThis code will expire in 2 minutes.'
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send reset email: {e}")

# This function sends an MFA code to an admin's email
def send_mfa_email(email, mfa_code):
    try:
        msg = Message('Admin MFA Code', sender='no-reply@example.com', recipients=[email])
        msg.body = f'Your admin MFA code is: {mfa_code}\nThis code will expire in 2 minutes.'
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send MFA email: {e}")



@app.route('/')
def home():
    # Fetch and parse the RSS feed
    feed = feedparser.parse('https://www.ntv.com.tr/seyahat.rss')
    news_items = feed.entries

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Dictionary to hold comments for each news item, including the comment id
    news_comments = {}
    for item in news_items:
        news_id = item.link  # Assuming the link is used as the news_id
        cursor.execute("""
            SELECT id, email, comment_text
            FROM comments
            WHERE news_id = ?
            """, (news_id,))
        comments = cursor.fetchall()
        news_comments[news_id] = comments

    conn.close()
    return render_template('home.html', news_items=news_items, news_comments=news_comments)


    


@app.route('/comment', methods=['POST'])
def post_comment():
    print("Session data:", session)

    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if the user is not logged in

    email = session['email']
    news_id = request.form.get('news_id')
    user_comment = request.form.get('comment')

    # Connect to the database and insert the comment
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (news_id, email, comment_text) VALUES (?, ?, ?)", 
                   (news_id, email, user_comment))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))
@app.route('/search_news', methods=['GET'])
def search_news():
    query = request.args.get('query', '').lower()
    feed = feedparser.parse('https://www.ntv.com.tr/seyahat.rss')
    news_items = feed.entries

    # Filter the news items based on the search query
    filtered_news_items = [item for item in news_items if query in item.title.lower()]

    # Prepare the comments for the filtered news items
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    news_comments = {}
    for item in filtered_news_items:
        news_id = item.link  # Assuming the link is used as the news_id
        cursor.execute("""
            SELECT id, email, comment_text
            FROM comments
            WHERE news_id = ?
            """, (news_id,))
        comments = cursor.fetchall()
        news_comments[news_id] = comments

    conn.close()

    # Render the same 'home.html' but only with the filtered news items
    return render_template('home.html', news_items=filtered_news_items, news_comments=news_comments)
@app.route('/admin_comment', methods=['POST'])
def post_admin_comment():
    if 'is_admin' not in session or not session['is_admin']:
        return "Unauthorized", 403

    admin_email = session['admin_email']
    news_id = request.form.get('news_id')
    admin_comment = request.form.get('comment')

    # Connect to the database and insert the admin comment
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments (news_id, email, comment_text) VALUES (?, ?, ?)", 
                   (news_id, admin_email, admin_comment))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))


@app.route('/comments/<news_id>')
def show_comments(news_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT comment_text, timestamp FROM comments WHERE news_id = ?", (news_id,))
    comments = cursor.fetchall()
    conn.close()

    return render_template('comments.html', comments=comments, news_id=news_id)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Generate a 2-digit reset code
        reset_code = str(random.randint(10, 99))
        reset_codes[email] = {'code': reset_code, 'expires': datetime.datetime.now() + datetime.timedelta(minutes=2)}
        send_reset_email(email, reset_code)

        # Redirect to the verify_reset_code page after sending the reset code
        return redirect(url_for('verify_reset_code'))
    else:
        return render_template('forgot_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operation = random.choice(['+', '-', '*'])
    captcha_question = f"{num1} {operation} {num2}"
    correct_answer = str(eval(captcha_question))


    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        captcha_response = request.form.get('captcha', '')

        # Log the login attempt
        # Inside the verify_reset_code function
        log_request(req_type="POST",
            endpoint="/login",
            status="Attempt",
            remote_addr=request.remote_addr,
            user_agent=request.user_agent.string)

        
        if captcha_response != session.get('captcha_answer', ''):
            message = 'Incorrect CAPTCHA.'
        else:
            hashed_password = hash_password(password)
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
            result = cursor.fetchone()
            conn.close()

            if result:
                session['email'] = email
                return redirect(url_for('home'))
            else:
                message = 'Failed to log in!'

    session['captcha_answer'] = correct_answer

    return render_template('user_login.html', message=message, captcha_question=captcha_question)


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    message = ''
    status = "Attempt"
    if request.method == 'POST':
        admin_email = request.form['admin_email']
        admin_password = request.form['admin_password']
        captcha_response = request.form['captcha_response']	

        if captcha_response != session.get('captcha_answer', ''):
            message = 'Incorrect CAPTCHA.'
            status = "Failed - Incorrect CAPTCHA"  # Update status for logging
        else:
            hashed_password = hash_password(admin_password)
            
            # Verify if the email and password are correct and if the user is an admin
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admins WHERE email = ? AND password = ?", (admin_email, hashed_password))
            admin = cursor.fetchone()
            conn.close()

            if admin:
                # Generate a random 6-digit MFA code
                mfa_code = '{:06d}'.format(random.randint(0, 999999))
                # Save the MFA code and expiration in the session
                session['mfa_code'] = mfa_code
                session['mfa_code_expires'] = (datetime.datetime.now() + datetime.timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
                session['mfa_attempts'] = 0
                # Send the SMS via Twilio
                body = f"Your admin MFA code is: {mfa_code}"
                send_sms_response = send_sms_via_twilio(my_phone_number, body)
                if send_sms_response:
                    session['admin_email'] = admin_email  # Store email in session to use in the next step
                    return redirect(url_for('verify_mfa'))
                else:
                    message = 'Failed to send SMS. Please try again.'
            else: 
                message = 'Invalid email or password.'
                status = 'Failed - Invalid Credentials'
            
        log_request(req_type="POST", endpoint="/admin_login", status=status, remote_addr=request.remote_addr, user_agent=request.user_agent.string)
    return render_template('admin_login.html', message=message)


@app.route('/logout', methods=['POST'])
def logout():
    # Remove user information from the session
    session.clear()

    # Redirect to the homepage or login page
    return redirect(url_for('home'))

@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    status = 'Normal'
    if 'admin_email' not in session or 'mfa_code' not in session or 'mfa_code_expires' not in session:
        flash('No MFA session in progress.')
        return redirect(url_for('admin_login'))

    admin_email = session['admin_email']
    mfa_code = session['mfa_code']
    mfa_code_expires = datetime.datetime.strptime(session['mfa_code_expires'], "%Y-%m-%d %H:%M:%S")

    # Initialize attempt counter if not already in session
    session.setdefault('mfa_attempts', 0)

    if request.method == 'POST':
        # Increment the attempt counter
        session['mfa_attempts'] += 1

        if session['mfa_attempts'] <= 3:
            entered_code = request.form.get('mfa_code')

            if entered_code == mfa_code and datetime.datetime.now() < mfa_code_expires:
                # MFA code is correct and not expired
                session['is_admin'] = True  # Set the admin as logged in
                session.pop('mfa_attempts', None)  # Reset the attempt counter
                status = "Success - MFA Verified"
                flash('MFA verification successful, admin logged in.')
                return redirect(url_for('home'))  # Redirect to the admin home page
            else:
                remaining_attempts = 3 - session['mfa_attempts']
                if session['mfa_attempts'] >= 3:
                    # Invalidate the MFA code after 3 failed attempts
                    session.pop('mfa_code', None)
                    session.pop('mfa_code_expires', None)
                    flash('MFA code has been invalidated due to multiple failed attempts.')
                else:
                    # Notify the user of the remaining attempts
                    status = "Failed - Incorrect MFA Code"
                    flash(f'Invalid or expired MFA code. {remaining_attempts} attempt(s) remaining.')
        else:
            status ='Maximum attempt limit reached. MFA code invalidated.'
            return redirect(url_for('admin_login'))
    log_request(req_type="POST",
                    endpoint="/verify_mfa",
                    status=status,  # Pass the specific status message here
                    remote_addr=request.remote_addr,
                    user_agent=request.user_agent.string)
    return render_template('verify_mfa.html')
    
@app.route('/admin_home')
def admin_home():
    return 'Welcome to the Admin Home!'
    
@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    # Check if the user is logged in as an admin
    if 'is_admin' not in session or not session['is_admin']:
        return "Unauthorized", 403

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Delete the comment with the given ID
    cursor.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

    
from flask import render_template  # Make sure this is imported at the top of your file

@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    message = None  # Initialize message
    if request.method == 'POST':
        email = request.form.get('email')
        user_code = request.form.get('reset_code')  # Change 'code' to 'reset_code' to match the form field name
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if email and user_code:
            if email in reset_codes and reset_codes[email]['expires'] > datetime.datetime.now():
                if reset_codes[email]['code'] == user_code:
                    if new_password and confirm_password and new_password == confirm_password:
                        # Passwords match, proceed with resetting password
                        conn = sqlite3.connect('database.db')
                        cursor = conn.cursor()
                        hashed_password = hash_password(new_password)
                        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
                        conn.commit()
                        conn.close()
                        message = 'Password reset successful'  # Set the success message
                        status = "Success"
                    else:
                        message = 'Passwords do not match or are missing'
                        status = "Failed"
                else:
                    message = 'Invalid reset code.'
                    status = "Failed"
            else:
                message = 'Reset code has expired or does not exist.'
                status = "Failed"
        else:
            message = 'Email or reset code is missing.'
            status = "Failed"

        # Here we determine if it's an abuse based on the status
        attempt_type = "Password Reset Abuse" if "Failed" in status and "Invalid reset code." in message else "Normal Request"
        log_request(req_type="POST",
                    endpoint="/verify_reset_code",
                    status=attempt_type,  # This is updated based on the result
                    remote_addr=request.remote_addr,
                    user_agent=request.user_agent.string)
    else:
        # Log the GET request as a normal request
        log_request(req_type="GET",
                    endpoint="/verify_reset_code",
                    status="Normal Request",
                    remote_addr=request.remote_addr,
                    user_agent=request.user_agent.string)

    # Render the template and pass the message to it
    return render_template('verify_reset_code.html', message=message)

@app.route('/forgot_admin_password', methods=['GET', 'POST'])
def forgot_admin_password():
    if request.method == 'POST':
        admin_email = request.form['admin_email']
        # Verify if the email is for an admin
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admins WHERE email = ?", (admin_email,))
        admin = cursor.fetchone()
        conn.close()

        if admin:
            # Generate a random 6-digit reset code
            reset_code = '{:06d}'.format(random.randint(0, 999999))
            # Save the reset code and expiration in the session
            session['admin_reset_code'] = reset_code
            session['admin_reset_code_expires'] = (datetime.datetime.now() + datetime.timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S")
            session['admin_email_for_reset'] = admin_email
            # Send the SMS via Twilio
            body = f"Your admin password reset code is: {reset_code}"
            send_sms_response = send_sms_via_twilio(my_phone_number, body)
            if send_sms_response:
                flash('Password reset code sent via SMS.')
                return redirect(url_for('verify_admin_reset_code'))
            else:
                flash('Failed to send SMS. Please try again.')
        else:
            flash('Invalid admin email.')
    return render_template('forgot_admin_password.html')

@app.route('/verify_admin_reset_code', methods=['GET', 'POST'])
def verify_admin_reset_code():
    if request.method == 'POST':
        entered_code = request.form.get('reset_code')
        if 'admin_reset_code' in session and 'admin_reset_code_expires' in session:
            reset_code_expires = datetime.datetime.strptime(session['admin_reset_code_expires'], "%Y-%m-%d %H:%M:%S")
            if entered_code == session['admin_reset_code'] and datetime.datetime.now() < reset_code_expires:
                # Reset code is correct and not expired
                session['is_admin'] = True  # Set the admin as logged in
                # Here, you can redirect to a page to allow password reset
                return redirect(url_for('admin_password_reset'))
            else:
                flash('Invalid or expired reset code.')
        else:
            flash('No reset session in progress.')
    return render_template('verify_admin_reset_code.html')

@app.route('/admin_password_reset', methods=['GET', 'POST'])
def admin_password_reset():
    if 'is_admin' not in session or not session['is_admin']:
        flash('You must be logged in as an admin to access this page.')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password and confirm_password and new_password == confirm_password:
            hashed_password = hash_password(new_password)
            admin_email = session.get('admin_email_for_reset')

            # Update the password in the database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE admins SET password = ? WHERE email = ?", (hashed_password, admin_email))
            conn.commit()
            conn.close()

            flash('Password reset successful.')
            return redirect(url_for('admin_login'))
        else:
            flash('Passwords do not match or are missing.')
    return render_template('admin_password_reset.html')

@app.route('/monitoring')
def monitoring():
    log_entries = {'login': [], 'verify_reset_code': [], 'admin_login': [], 'other': []}
    with open('honeypot.log', 'r') as log_file:
        for line in log_file:
            if '/login' in line:
                log_entries['login'].append(line.strip())
            elif '/verify_reset_code' in line:
                log_entries['verify_reset_code'].append(line.strip())
            elif '/admin_login' in line:
                log_entries['admin_login'].append(line.strip())
            else:
                log_entries['other'].append(line.strip())

    return render_template('monitoring.html', log_entries=log_entries)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
