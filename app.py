from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="digital_wallet_app"
)
cursor = db.cursor(dictionary=True)  # dictionary=True to access rows by column name

# ---------- ROUTES ----------

# Home
@app.route('/')
def home():
    return render_template("home.html")

# Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password, role) VALUES (%s,%s,%s,%s)",
                (username, email, password, role)
            )
            db.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username or Email already exists.", "danger")

    return render_template("register.html")

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome {user['username']}!", "success")

            # Redirect based on role
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'delivery':
                return redirect(url_for('delivery_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# Customer dashboard
@app.route('/customer')
def customer_dashboard():
    if 'role' in session and session['role'] == 'customer':
        return render_template("search.html", username=session['username'])
    return "Unauthorized", 403

# Admin dashboard
@app.route('/admin')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        return render_template("admin.html", username=session['username'])
    return "Unauthorized", 403

# Delivery dashboard
@app.route('/delivery')
def delivery_dashboard():
    if 'role' in session and session['role'] == 'delivery':
        return render_template("delivery_dashboard.html", username=session['username'])
    return "Unauthorized", 403




# Run Flask
if __name__ == "__main__":
    app.run(debug=True)
