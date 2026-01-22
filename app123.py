from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "super_secret_key"

# -------------------------
# SIMPLE IN-MEMORY USER STORAGE (for demo)
# -------------------------
users = {
    'admin@gmail.com': {'name': 'Admin User', 'password': 'admin123', 'role': 'admin'}
}

# -------------------------
# HOME
# -------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# -------------------------
# REGISTER
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if email in users:
            flash("Email already registered!", "warning")
            return redirect(url_for('register'))

        users[email] = {'name': name, 'password': password, 'role': role}
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# -------------------------
# LOGIN
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        user = users.get(email)

        if user and user['password'] == password and user['role'] == role:
            session['user'] = {'email': email, 'name': user['name'], 'role': role}
            flash(f"Welcome {user['name']} ({role.capitalize()})!", "success")

            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'customer':
                return redirect(url_for('customer_dashboard'))
            elif role == 'delivery_person':
                return redirect(url_for('delivery_dashboard'))
        else:
            flash("Invalid email, password, or role!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


# -------------------------
# LOGOUT
# -------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# -------------------------
# DASHBOARDS
# -------------------------
@app.route('/admin_dashboard')
def admin_dashboard():
    user = session.get('user', {})
    if user.get('role') != 'admin':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', user=user)


@app.route('/customer_dashboard')
def customer_dashboard():
    user = session.get('user', {})
    if user.get('role') != 'customer':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    return render_template('customer_dashboard.html', user=user)


@app.route('/delivery_dashboard')
def delivery_dashboard():
    user = session.get('user', {})
    if user.get('role') != 'delivery_person':
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))
    return render_template('delivery_dashboard.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
