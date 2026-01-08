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
# User Registration & Verification
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password, role, is_verified) VALUES (%s, %s, %s, %s, %s, FALSE)",
            (first_name, last_name, email, hashed_pw, role)
        )
        db.commit()
        user_id = cursor.lastrowid

        code = generate_code()
        cursor.execute("INSERT INTO verification_codes (user_id, code) VALUES (%s, %s)", (user_id, code))
        db.commit()

        send_email(
            email,
            "Verify Your Tesco Food City Account",
            f"<h3>Welcome!</h3><p>Your verification code: <b>{code}</b></p>"
        )

        flash(f"Registration successful! Verification code sent to {email}.", "success")
        return redirect(url_for("verify", email=email))

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
# Manual Login
# -----------------------------
@app.route("/manual_login", methods=["GET", "POST"])
def manual_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user["password"], password) and user["role"] == role:
            session["user"] = {"name": user["first_name"], "email": email, "role": role}
            flash("Login successful!", "success")
            return redirect_role_dashboard(role)
        else:
            flash("Invalid credentials or role mismatch.", "danger")

    return render_template("manual_login.html")

# -----------------------------
# Dashboards
# -----------------------------
@app.route("/customer_dashboard")
def customer_dashboard():
    if session.get("user", {}).get("role") != "customer":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))
    return render_template("customer_dashboard.html", user=session["user"])

@app.route("/admin_dashboard")
def admin_dashboard():
    if session.get("user", {}).get("role") != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))
    return render_template("admin_dashboard.html", user=session["user"])

@app.route("/delivery_dashboard")
def delivery_dashboard():
    if session.get("user", {}).get("role") != "delivery_person":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("home"))
    return render_template("delivery_dashboard.html", user=session["user"])

# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

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
