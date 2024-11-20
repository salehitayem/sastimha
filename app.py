from flask import Flask, render_template, redirect, request, flash, g
import secrets
import sqlite3

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)


DATABASE = 'data.db'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)  # Connect to the database
        g.db.row_factory = sqlite3.Row  # Enable dict-like access to rows
    return g.db

def log_visitor():
    """Logs the visitor's IP address, User-Agent, and Referer into the database."""
    try:
        db = get_db()
        visitor_ip = request.remote_addr or "Unknown"  # Fallback for IP address
        user_agent = request.headers.get('User-Agent') or "Unknown"
        referer = request.headers.get('Referer') or "Direct Access"

        # Insert the visitor details into the database
        db.execute(
            '''
            INSERT INTO visitor_logs (ip_address, user_agent, referer)
            VALUES (?, ?, ?)
            ''',
            (visitor_ip, user_agent, referer)
        )
        db.commit()
    except Exception as e:
        print(f"Error logging visitor: {e}")  # Log error to the console
        raise


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
            db.execute(
                'INSERT INTO clients (name, email, subject, message, status) VALUES (?, ?, ?, ?, ?)',
                (name, email, subject, message, 'waiting')
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
            db.execute(
                'INSERT INTO clients (name, email, subject, message, status) VALUES (?, ?, ?, ?, ?)',
                (name, email, subject, message, 'waiting')
            )
            db.commit()
            flash('لقد تم إرسال رسالتك بنجاح!', 'success')  # Flash success
            return redirect('/ar')  # Redirect after successful submission
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')  # Flash database error
            return redirect('/ar')  # Redirect back to the form
        



@app.errorhandler(404)
def page_not_found(e):
    return redirect('/')




if __name__ == "__main__":
    app.run(debug=True)
