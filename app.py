import os
import random
import string
import secrets
from datetime import datetime, timedelta
from flask import Flask, jsonify, redirect, url_for, session, request, render_template, flash

import mysql.connector

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, session, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)
app.secret_key = 'TescoFoodCitySecret123!@#'  # 🔑 needed for session


# -----------------------------
# Google OAuth Config
# -----------------------------
CLIENT_ID = 'YOUR_CLIENT_ID'
CLIENT_SECRET = 'YOUR_CLIENT_SECRET'
REDIRECT_URI = "http://127.0.0.1:5000/callback"
AUTHORIZATION_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow HTTP for dev

# -----------------------------
# Database connection
# -----------------------------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",   # Your MySQL password
    database="digital_wallet_app"
)
cursor = db.cursor(dictionary=True)
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="", 
        database="digital_wallet_app"
    )

# ... then your routes ...

# -----------------------------
# SendGrid client
# -----------------------------
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SG = SendGridAPIClient(SENDGRID_API_KEY)
SENDER_EMAIL = "your-email@example.com"

# -----------------------------
# Helper Functions
# -----------------------------
def generate_code():
    return ''.join(random.choices(string.digits, k=6))

def send_email(to_email, subject, content):
    """Send email using SendGrid"""
    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    try:
        response = SG.send(message)
        print(f"Email sent → Status: {response.status_code}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def redirect_role_dashboard(role):
    """Redirect user to correct dashboard based on role"""
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    elif role == "delivery_person":
        return redirect(url_for("delivery_dashboard"))
    else:
        return redirect(url_for("customer_dashboard"))

# -----------------------------
# Routes: Home / Products / Search



# -----------------------------
@app.route('/')
def landing_page():
    """Render the landing page."""
    username = session.get("user", {}).get("name", "Guest")
    return render_template('landing.html', username=username)

@app.route('/search')
def search_page():
    username = session.get("user", {}).get("name", "Guest")
    return render_template('search.html', username=username)


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    cart = session.get('cart', [])

    product_id = int(data['id'])
    product_qty = int(data['qty'])
    product_name = data['name']
    product_price = float(data['price'])

    # Check if product already in cart
    for item in cart:
        if item['id'] == product_id:
            item['qty'] += product_qty
            break
    else:
        cart.append({
            'id': product_id,
            'name': product_name,
            'price': product_price,
            'qty': product_qty
        })

    session['cart'] = cart
    session.modified = True

    return jsonify({'message': f"{product_name} added to cart successfully!"})


@app.route('/add_to_wishlist', methods=['POST'])
def add_to_wishlist():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    wishlist = session.get('wishlist', [])

    product_id = int(data['id'])
    product_name = data['name']

    # Avoid duplicates
    if not any(item['id'] == product_id for item in wishlist):
        wishlist.append({
            'id': product_id,
            'name': product_name
        })

    session['wishlist'] = wishlist
    session.modified = True

    return jsonify({'message': f"{product_name} added to wishlist successfully!"})





































@app.route('/remove-from-cart', methods=['POST'])
def remove_from_cart():
    item_id = request.form.get('item_id')

    cart = session.get('cart', [])
    cart = [item for item in cart if str(item['id']) != str(item_id)]

    session['cart'] = cart
    return redirect(url_for('cart_page'))



@app.route('/checkout')
def checkout():
    cart_items = session.get('cart', [])
    total = sum(item['price'] * item['qty'] for item in cart_items)
    return render_template('checkout.html', total=total)


@app.route('/cart')
def cart_page():
    cart = session.get('cart', [])
    total = sum(float(item['price']) * int(item['qty']) for item in cart)
    return render_template('cart.html', cart_items=cart, total=total)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/delivery')
def delivery():
    return render_template('delivery.html')


@app.route('/search_products', methods=['GET'])
def search_products():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    cursor.execute(
        "SELECT id, name, price, image_url FROM products WHERE name LIKE %s",
        ('%' + query + '%',)
    )
    products = cursor.fetchall()
    results = [
        {"id": p["id"], "name": p["name"], "price": float(p["price"]), "image_url": p["image_url"]}
        for p in products
    ]
    return jsonify(results)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    cursor.execute(
        
        
              "SELECT * FROM products WHERE id = %s",
        (product_id,)
    )
    product = cursor.fetchone()

    if product is None:
        return "<h3>Product not found!</h3>", 404

    return render_template(
        'product_detail.html',
        product=product
    )





# Cart page  ✅ REQUIRED for url_for('cart')
@app.route('/cart')
def cart():
    return render_template('cart.html')
    

# -----------------------------
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

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = request.args.get("email")
    if not email:
        flash("No email specified for verification.", "danger")
        return redirect(url_for("register"))

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form["code"]
        cursor.execute("SELECT * FROM verification_codes WHERE user_id=%s AND code=%s", (user["id"], code))
        if cursor.fetchone():
            cursor.execute("UPDATE users SET is_verified=TRUE WHERE id=%s", (user["id"],))
            db.commit()
            session["user"] = {"name": user["first_name"], "email": email, "role": user["role"]}
            flash("Email verified successfully!", "success")
            return redirect_role_dashboard(user["role"])
        else:
            flash("Invalid verification code.", "danger")

    return render_template("verify.html", email=email)



@app.route('/category/daily-deals')
def daily_deals():
    return render_template('dailydeals.html')

@app.route('/category/dairy')
def dairy():
    return render_template('dairy.html')

@app.route('/category/frozen')
def frozen():
    return render_template('frozenPage.html')

@app.route('/category/grocery')
def grocery():
    return render_template('grocery.html')


# -----------------------------
# ADMIN DASHBOARD ROUTES
# -----------------------------

# --- ADD THIS FUNCTION TO app.py ---

@app.route('/admin_dashboard')
def admin_dashboard():
    # Now this line will work:
    conn = get_db_connection() 
    # 1. Security Check
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 2. Get Current User
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        current_user = cursor.fetchone()

        # 3. Fetch Data
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()

        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM orders ORDER BY id DESC")
        orders = cursor.fetchall()

        # 4. Stats Calculation
        cursor.execute("SELECT SUM(total_price) as revenue FROM orders")
        res = cursor.fetchone()
        total_revenue = res['revenue'] if res and res['revenue'] else 0
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE role != 'admin'")
        customer_count = cursor.fetchone()['count']

        stats = {
            "revenue": "{:,.2f}".format(float(total_revenue)),
            "orders": len(orders),
            "products": len(products),
            "customers": customer_count
        }

        # 5. Render
        return render_template(
            "admin_dashboard.html",
            user=current_user,
            stats=stats,
            products=products,
            orders=orders,
            users=users
        )
    finally:
        cursor.close()
        conn.close()

# -----------------------------
# PRODUCT ACTIONS
# -----------------------------

@app.route('/add_product', methods=['POST'])
def add_product():
    if 'user_id' not in session: 
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        image_url = request.form['image_url']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            query = "INSERT INTO products (name, price, image_url) VALUES (%s, %s, %s)"
            cursor.execute(query, (name, price, image_url))
            conn.commit()
            flash('Product added successfully!', 'success')
        except Exception as e:
            flash(f'Error adding product: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('admin_dashboard'))

@app.route('/delete_product/<int:id>')
def delete_product(id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM products WHERE id = %s", (id,))
        conn.commit()
        flash('Product deleted.', 'warning')
    except Exception as e:
        flash('Error deleting product.', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('admin_dashboard'))

# -----------------------------
# ORDER ACTIONS
# -----------------------------

@app.route('/update_order_status/<int:id>', methods=['POST'])
def update_order_status(id):
    if 'user_id' not in session: return redirect(url_for('login'))

    new_status = request.form.get('status')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (new_status, id))
        conn.commit()
        flash(f'Order #{id} updated to {new_status}.', 'info')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

# -----------------------------
# USER ACTIONS
# -----------------------------

@app.route('/delete_user/<int:id>')
def delete_user(id):
    if 'user_id' not in session: return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Check role before deleting
        cursor.execute("SELECT role FROM users WHERE id = %s", (id,))
        user_to_delete = cursor.fetchone()
        
        if user_to_delete and user_to_delete['role'] == 'admin':
            flash("You cannot delete an admin account.", "danger")
        else:
            cursor.execute("DELETE FROM users WHERE id = %s", (id,))
            conn.commit()
            flash('User removed.', 'success')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

# -----------------------------
# AUTHENTICATION
# -----------------------------






# -----------------------------
# MISSING ROUTE: Update Personal Info
# -----------------------------
@app.route('/update_info', methods=['POST'])
def update_info():
    # 1. Check if user is logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    new_name = request.form.get('name')
    new_email = request.form.get('email')

    try:
        # 2. Update Name
        if new_name:
            cursor.execute("UPDATE users SET username = %s WHERE id = %s", (new_name, user_id))
            session['user']['name'] = new_name # Update session immediately

        # 3. Update Email (if provided)
        if new_email:
            cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, user_id))
        
        db.commit()
        flash("Information updated successfully!", "success")
        
    except mysql.connector.Error as err:
        flash(f"Error updating info: {err}", "danger")

    return redirect(url_for('my_account'))

# -----------------------------
# Manual Login
# -----------------------------
# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            # Save session details
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            flash(f"Welcome {user['username']}!", "success")

            # Clean the role string (remove spaces, make lowercase)
            role = user['role'].strip().lower()

            if role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif role == 'delivery':
                return redirect(url_for('delivery_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")

# -----------------------------
# Dashboards
# -----------------------------

@app.route("/customer_dashboard")
def customer_dashboard():
    if session.get("role") != "customer":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("login"))

    user_data = {"username": session.get("username"), "role": session.get("role")}
    return render_template("search.html", user=user_data)




@app.route("/delivery_dashboard")
def delivery_dashboard():
    # We check for 'delivery' because that is what we saved in the login function
    if session.get("role") != "delivery":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("login"))

    user_data = {"username": session.get("username"), "role": session.get("role")}
    return render_template("delivery_dashboard.html", user=user_data)




















































































































































# -----------------------------
# My Account Page
# -----------------------------
@app.route('/my_account')
def my_account():
    # Check if user is logged in
    if 'username' not in session:
        flash("Please login to view your account.", "warning")
        return redirect(url_for('login'))
    
    # Render the new account page HTML
    return render_template("account.html", username=session['username'])

# Placeholder routes for the buttons in your account page (to avoid errors)
@app.route('/personal_data', methods=['GET', 'POST'])
def personal_data():
    if 'user_id' not in session:
        flash("Please login first.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        
        try:
            # Update user in database
            cursor.execute("UPDATE users SET username=%s, email=%s WHERE id=%s", 
                           (new_username, new_email, session['user_id']))
            conn.commit()
            
            # Update session data so the name changes in the navbar immediately
            session['username'] = new_username
            flash("Profile updated successfully!", "success")
        except Exception as e:
            flash("Error updating profile. Email might already exist.", "danger")
            print(f"Error: {e}")

    # Fetch current user details to pre-fill the form
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("personal_data.html", user=user)

@app.route('/change_password', methods=['POST'])
def change_password():
    # 1. Check if user is logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    current_pass = request.form.get('current_password')
    new_pass = request.form.get('new_password')
    confirm_pass = request.form.get('confirm_password')

    # 2. Check if new passwords match
    if new_pass != confirm_pass:
        flash("New passwords do not match!", "danger")
        return redirect(url_for('my_account'))

    try:
        # 3. Get current password hash from DB
        cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()

        if result:
            stored_hash = result['password']
            
            # 4. Verify current password
            if check_password_hash(stored_hash, current_pass):
                # 5. Hash new password and update
                new_hash = generate_password_hash(new_pass)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_hash, user_id))
                db.commit()
                flash("Password changed successfully!", "success")
            else:
                flash("Incorrect current password.", "danger")
        
    except mysql.connector.Error as err:
        flash(f"Error changing password: {err}", "danger")

    return redirect(url_for('my_account'))

# ------------------------------------------------










# Logout
# -----------------------------
# -----------------------------
# Logout
# -----------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))
# -----------------------------
# Catch-all
# -----------------------------
@app.route('/<path:path>')
def catch_all(path):
    return f"Route /{path} not found. Go to <a href='/'>home</a>."

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)
