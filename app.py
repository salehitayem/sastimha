from flask import Flask, render_template, redirect, request, flash, g, jsonify, session, url_for
import secrets, sqlite3, random
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config
from flask_mail import Mail, Message
from datetime import datetime 

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)
app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)

app.config.from_object(Config)

mail = Mail(app)


DATABASE = 'data.db'



def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)  # Connect to the database
        g.db.row_factory = sqlite3.Row  # Enable dict-like access to rows
    return g.db


def send_verification_email(email, code):
    msg = Message(
        subject='login verification',
        recipients=[email]
    )
    msg.body = f"Your login verification code is: {code}"
    mail.send(msg)




def log_visitor():
    try:
        db = get_db()
        visitor_ip = request.remote_addr or "Unknown"
        user_agent = request.headers.get('User-Agent') or "Unknown"
        referer = request.headers.get('Referer') or "Direct Access"

        db.execute(
            '''
            INSERT INTO visitor_logs (ip_address, user_agent, referer)
            VALUES (?, ?, ?)
            ''',
            (visitor_ip, user_agent, referer)
        )
        db.commit()
    except Exception as e:
        print(f"Error logging visitor: {e}")
        raise

@app.route('/', methods=['GET'])
def home():
    try:
        log_visitor()
    except Exception as e:
        print(f"Error in log_visitor: {e}")
    return render_template('index.html')



@app.route('/', methods=['POST', 'GET', 'UPDATE', 'DELETE'])
def home():
    if request.method != "GET":
        return redirect('/')

    try:
        log_visitor()  # Log visitor information
    except Exception as e:
        print(f"Error in log_visitor: {e}")  # Log error for debugging

    return render_template('index.html')

@app.route('/ar', methods=['POST', 'GET', 'UPDATE', 'DELETE'])
def ar():
    if request.method != "GET":
        return redirect('/ar')

    try:
        log_visitor()  # Log visitor information
    except Exception as e:
        print(f"Error in log_visitor: {e}")  # Log error for debugging

    return render_template('ar.html')

# error = 'عليك تعبئة كافة الحقول لاتمام الطلب'

@app.route('/contact', methods=['POST','GET','UPDATE','DELETE'])
def contact():
    if request.method != 'POST':
        flash('Method Not Allowed!', 'error')  # Flash error message
        return redirect('/')
    else:
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Check for missing fields
        if not name or not email or not subject or not message:
            flash('Make sure to fill all the fields!', 'error')  # Flash error
            return redirect('/contact')  # Redirect back to the form

        try:
            db = get_db()
            current_date = datetime.now().strftime('%Y-%m-%d')  # Get the current date in 'YYYY-MM-DD' format
            db.execute(
                'INSERT INTO clients (name, email, subject, message, status, date) VALUES (?, ?, ?, ?, ?, ?)',
                (name, email, subject, message, 'waiting', current_date)
            )
            db.commit()
            flash('Your message has been successfully submitted!', 'success')  # Flash success
            return redirect('/')  # Redirect after successful submission
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')  # Flash database error
            return redirect('/')  # Redirect back to the form
        

@app.route('/contacta', methods=['POST','GET','UPDATE','DELETE'])
def contacta():
    if request.method != 'POST':
        flash('Method Not Allowed!', 'error')  # Flash error message
        return redirect('/')
    else:
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Check for missing fields
        if not name or not email or not subject or not message:
            flash('يجب ملء جميع الحقول!', 'error')  # Flash error
            return redirect('/contact')  # Redirect back to the form

        try:
            db = get_db()
            current_date = datetime.now().strftime('%Y-%m-%d')  # Get the current date in 'YYYY-MM-DD' format
            db.execute(
                'INSERT INTO clients (name, email, subject, message, status, date) VALUES (?, ?, ?, ?, ?, ?)',
                (name, email, subject, message, 'waiting', current_date)
            )
            db.commit()
            flash('لقد تم إرسال رسالتك بنجاح!', 'success')  # Flash success
            return redirect('/ar')  # Redirect after successful submission
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')  # Flash database error
            return redirect('/ar')  # Redirect back to the form
        


        
# @app.route('/register', methods=["POST", "GET"])
# def register():
#     if request.method == "GET":
#         # Render the registration form
#         return render_template('register.html')
    
#     elif request.method == "POST":
#         # Get form data
#         email = request.form.get('email')
#         username = request.form.get('username')
#         password = request.form.get('password')

#         # Validate form data
#         if not email or not username or not password:
#             flash("All fields are required!", "error")
#             return redirect('/register')

#         # Hash the password
#         password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

#         # Check if username or email already exists
#         db = get_db()
#         existing_user = db.execute(
#             'SELECT * FROM admin_users WHERE username = ? OR email = ?', (username, email)
#         ).fetchone()

#         if existing_user:
#             flash("Username or email already exists!", "error")
#             return redirect('/register')

#         # Insert new admin into the database
#         db.execute(
#             'INSERT INTO admin_users (email, username, password_hash) VALUES (?, ?, ?)',
#             (email, username, password_hash)
#         )
#         db.commit()
#         flash("Registration successful! You can now log in.", "success")
#         return redirect('/loginx')


@app.route('/loginx', methods=["POST", "GET"])
def loginx():
    if request.method == "GET":
        return render_template('loginx.html')

    elif request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        admin = db.execute(
            'SELECT * FROM admin_users WHERE username = ?', (username,)
        ).fetchone()

        if admin and check_password_hash(admin['password_hash'], password):
            verification_code = str(random.randint(100000, 999999))
            db.execute(
                'UPDATE admin_users SET verification_code = ? WHERE id = ?',
                (verification_code, admin['id'])
            )
            db.commit()

            send_verification_email(admin['email'], verification_code)

            session['pending_verification_user_id'] = admin['id']
            flash("A verification code has been sent to your email. Please verify to log in.", "info")
            return redirect(url_for('verify'))
        else:
            flash("Invalid username or password!", "error")
            return redirect(url_for('loginx'))



@app.route('/verify', methods=["POST", "GET"])
def verify():
    if request.method == "GET":
        if not session.get('pending_verification_user_id'):
            flash("No pending verification. Please log in again.", "error")
            return redirect(url_for('loginx'))
        return render_template('verify.html')

    elif request.method == "POST":
        code = request.form.get('code')
        user_id = session.get('pending_verification_user_id')

        db = get_db()
        admin = db.execute(
            'SELECT * FROM admin_users WHERE id = ? AND verification_code = ?', (user_id, code)
        ).fetchone()

        if admin:
            db.execute(
                'UPDATE admin_users SET verification_code = NULL WHERE id = ?',
                (user_id,)
            )
            db.commit()

            session.pop('pending_verification_user_id', None)
            session['admin_logged_in'] = True
            session['admin_username'] = admin['username']
            flash("Login successful!", "success")
            return redirect(url_for('waiting_clients'))
        else:
            flash("Invalid verification code!", "error")
            return redirect(url_for('verify'))


@app.route('/logoutx', methods=["GET"])
def logoutx():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('loginx'))



@app.route('/waiting_clients', methods=["GET"])
def waiting_clients():
    if not session.get('admin_logged_in'):
        flash("You need to log in to access this page!", "error")
        return redirect(url_for('loginx'))

    db = get_db()
    clients = db.execute('SELECT * FROM clients WHERE status = ?', ('waiting',)).fetchall()
    return render_template('waiting_clients.html', clients=clients)

@app.route('/processing_clients', methods=["GET"])
def processing_clients():
    if not session.get('admin_logged_in'):
        flash("You need to log in to access this page!", "error")
        return redirect(url_for('loginx'))

    db = get_db()
    clients = db.execute('SELECT * FROM clients WHERE status = ?', ('processing',)).fetchall()
    return render_template('processing_clients.html', clients=clients)

@app.route('/done_clients', methods=["GET"])
def done_clients():
    if not session.get('admin_logged_in'):
        flash("You need to log in to access this page!", "error")
        return redirect(url_for('loginx'))

    db = get_db()
    clients = db.execute('SELECT * FROM clients WHERE status = ?', ('done',)).fetchall()
    return render_template('done_clients.html', clients=clients)

@app.route('/visitor_logs', methods=['GET'])
def visitor_logs():
    if not session.get('admin_logged_in'):
        flash("You need to log in to access this page!", "error")
        return redirect(url_for('loginx'))

    db = get_db()
    logs = db.execute(
        'SELECT id, ip_address, visit_time, user_agent, referer FROM visitor_logs ORDER BY visit_time DESC'
    ).fetchall()
    total_logs = db.execute('SELECT COUNT(*) FROM visitor_logs').fetchone()[0]

    return render_template('visitor_logs.html', logs=logs, total_logs=total_logs)




@app.route('/update_status', methods=["POST"])
def update_status():
    if not session.get('admin_logged_in'):
        return jsonify({"success": False, "message": "Unauthorized access"}), 403

    data = request.get_json()
    client_id = data.get('id')
    new_status = data.get('status')
    new_notes = data.get('notes')

    if not client_id or not new_status:
        return jsonify({"success": False, "message": "Invalid data"}), 400

    db = get_db()
    client = db.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()

    if not client:
        return jsonify({"success": False, "message": "Client not found"}), 404

    try:
        db.execute('UPDATE clients SET status = ?, notes = ? WHERE id = ?', (new_status, new_notes, client_id))
        db.commit()
        return jsonify({"success": True, "message": "Status and notes updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to update status: {str(e)}"}), 500

@app.route('/delete_client', methods=["POST"])
def delete_client():
    if not session.get('admin_logged_in'):
        return jsonify({"success": False, "message": "Unauthorized access"}), 403

    data = request.get_json()
    client_id = data.get('id')

    if not client_id:
        return jsonify({"success": False, "message": "Invalid client ID"}), 400

    db = get_db()
    client = db.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()

    if not client:
        return jsonify({"success": False, "message": "Client not found"}), 404

    try:
        db.execute('DELETE FROM clients WHERE id = ?', (client_id,))
        db.commit()
        return jsonify({"success": True, "message": "Client deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to delete client: {str(e)}"}), 500


@app.errorhandler(404)
def page_not_found(e):
    return redirect('/')
    




if __name__ == "__main__":
    app.run(debug=True)
