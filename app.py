import os
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask import send_file
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
    database="digital_wallet_app",
     autocommit=True,
    connection_timeout=30

    
)
cursor = db.cursor(dictionary=True)
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="", 
        database="digital_wallet_app",
         autocommit=True,
    connection_timeout=30
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

@app.route('/cart')
def cart_page():
    cart = session.get('cart', [])
    total = sum(float(item['price']) * int(item['qty']) for item in cart)
    return render_template('cart.html', cart_items=cart, total=total)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    cart = session.get('cart', [])
    total_price = sum(item['price'] for item in cart)

    if request.method == 'POST':
        customer_name = request.form['customer_name']
        address = request.form['address']
        phone = request.form['phone']
        payment_method = request.form['payment_method']
        
        # --- Database Logic (Save Order) ---
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Insert Order
        cursor.execute('''
            INSERT INTO orders (user_id, total_price, status, payment_method, customer_name, address, phone) 
            VALUES (%s, %s, 'Pending', %s, %s, %s, %s)
        ''', (session['user_id'], total_price, payment_method, customer_name, address, phone))
        
        order_id = cursor.lastrowid
        
        # 2. Insert Order Items
        for item in cart:
            cursor.execute('''
                INSERT INTO order_items (order_id, item_name, price, quantity)
                VALUES (%s, %s, %s, 1)
            ''', (order_id, item['name'], item['price']))
            
        conn.commit()
        cursor.close()
        conn.close()
        
        # --- Clear Cart ---
        session.pop('cart', None)
        
        # --- SHOW SUCCESS PAGE (Updated Line) ---
        # We pass 'total_price' to the new template so it can display it
        return render_template('order_success.html', total_price=total_price)

    # GET Request (Show the form)
    if not cart:
        return redirect(url_for('landing_page'))
        
    user = {'username': session.get('username'), 'email': session.get('email')}
    return render_template('checkout.html', cart=cart, total=total_price, user=user)



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
        "SELECT id, name, price FROM products WHERE name LIKE %s",
        ('%' + query + '%',)
    )
    products = cursor.fetchall()
    results = [
        {"id": p["id"], "name": p["name"], "price": float(p["price"])}
        for p in products
    ]
    return jsonify(results)

# --- 1. PRODUCT PAGE (Fetches Product + Reviews) ---
@app.route('/product/<int:product_id>')
def product_detail(product_id):  # <--- CHANGED TO SINGULAR to match your HTML
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # A. Fetch Product
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        return "Product not found", 404

    # B. Fetch Reviews for this product
    cursor.execute("SELECT * FROM reviews WHERE product_id = %s ORDER BY id DESC", (product_id,))
    reviews_list = cursor.fetchall()

    cursor.close()
    conn.close()

    # C. Calculate Average Rating
    total_rating = sum(r['rating'] for r in reviews_list)
    if reviews_list:
        avg_rating = round(total_rating / len(reviews_list), 1)
        product['rating'] = avg_rating
        product['reviews'] = len(reviews_list)
    else:
        product['rating'] = "No Ratings"
        product['reviews'] = 0

    # D. Attach reviews to the product object
    product['reviews_list'] = reviews_list

    # Ensure this matches your actual file name (e.g., product_detail.html)
    return render_template('product_detail.html', product=product)


# --- 2. ADD REVIEW ROUTE (No changes needed here, this is perfect) ---
@app.route('/add_review', methods=['POST'])
def add_review():
    # A. Check if user is logged in
    user_logged_in = False
    username = "Anonymous"

    if 'user_id' in session:
        user_logged_in = True
        username = session.get('username', 'User')
    elif 'user' in session: # Google OAuth structure
        user_logged_in = True
        username = session['user'].get('name', 'User')

    if not user_logged_in:
        return jsonify({'message': 'Please log in to review'}), 401

    # B. Get Data
    data = request.get_json()
    product_id = data.get('product_id')
    rating = data.get('rating')
    comment = data.get('comment')
    current_date = datetime.now().strftime("%Y-%m-%d")

    # C. Validation
    if not rating or not comment:
        return jsonify({'message': 'Rating and comment are required'}), 400

    # D. Save to Database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        sql = """
            INSERT INTO reviews (product_id, username, rating, comment, date)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (product_id, username, rating, comment, current_date))
        conn.commit()
        
        cursor.close()
        conn.close()
        return jsonify({'message': 'Review submitted successfully!'}), 200

    except Exception as e:
        print(f"Error saving review: {e}")
        return jsonify({'message': 'Database error'}), 500
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

@app.route('/download_invoice/<int:order_id>')
def download_invoice(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get Order Info
    cursor.execute("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, session['user_id']))
    order = cursor.fetchone()
    
    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect(url_for('my_account'))
        
    # Get Order Items
    cursor.execute("SELECT * FROM order_items WHERE order_id = %s", (order_id,))
    items = cursor.fetchall()
    
    cursor.close()
    conn.close()

    # Generate PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Header
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 750, "Tesco Food City - Invoice")
    
    p.setFont("Helvetica", 12)
    p.drawString(50, 730, f"Order ID: #{order['id']}")
    p.drawString(50, 715, f"Date: {order['date_ordered']}")
    p.drawString(50, 700, f"Customer: {session.get('username')}")
    p.drawString(50, 685, f"Status: {order['status']}")
    
    p.line(50, 670, 550, 670)
    
    # Items
    y = 650
    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, y, "Item")
    p.drawString(350, y, "Qty")
    p.drawString(450, y, "Price")
    y -= 20
    
    p.setFont("Helvetica", 12)
    for item in items:
        p.drawString(50, y, item['item_name'])
        p.drawString(350, y, str(item['quantity']))
        p.drawString(450, y, f"Rs. {item['price']}")
        y -= 20
        
    p.line(50, y, 550, y)
    y -= 20
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(350, y, "Total Amount:")
    p.drawString(450, y, f"Rs. {order['total_price']}")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"invoice_{order_id}.pdf", mimetype='application/pdf')




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
    if 'user_id' not in session:
        flash("Please login to view your account.", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    orders = []
    
    try:
        # 1. Fetch User's Orders
        cursor.execute("SELECT * FROM orders WHERE user_id = %s ORDER BY date_ordered DESC", (session['user_id'],))
        orders = cursor.fetchall()
        
        # 2. Fetch Items for each Order (to display "Milk, Rice" etc.)
        for order in orders:
            cursor.execute("SELECT product_name, quantity FROM order_items WHERE order_id = %s", (order['id'],))
            items = cursor.fetchall()
            
            # Create a string like "Fresh Milk (x2), Rice (x1)"
            item_list = [f"{i['product_name']} (x{i['quantity']})" for i in items]
            order['items_str'] = ", ".join(item_list)
            
    except Exception as e:
        print(f"Error fetching account data: {e}")
    finally:
        cursor.close()
        conn.close()

    return render_template("account.html", username=session.get('username'), orders=orders)




# ------------------------------------------------


# -----------------------------
# 1. UPDATE PERSONAL INFO
# -----------------------------
@app.route('/update_info', methods=['POST'])
def update_info():
    # Security: Check if user is logged in
    if 'user_id' not in session:
        flash("Please log in to update your profile.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    new_name = request.form.get('name')
    new_email = request.form.get('email')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # 1. Update the database
        # We update both username and email for the logged-in user
        query = "UPDATE users SET username = %s, email = %s WHERE id = %s"
        cursor.execute(query, (new_name, new_email, user_id))
        conn.commit()

        # 2. Verify and Update Session
        # If the database update was successful, we update the live session
        # so the name in the navbar changes immediately without re-login.
        session['username'] = new_name
        
        # Check if rows were actually affected (optional verification)
        if cursor.rowcount > 0:
            flash("Profile details updated successfully!", "success")
        else:
            flash("No changes were made.", "info")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash("Error updating profile. This email might already be in use.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('my_account'))


# -----------------------------
# 2. CHANGE PASSWORD
# -----------------------------
@app.route('/change_password', methods=['POST'])
def change_password():
    # Security: Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_pass = request.form.get('current_password')
    new_pass = request.form.get('new_password')
    confirm_pass = request.form.get('confirm_password')

    # 1. Basic Validation
    if new_pass != confirm_pass:
        flash("New passwords do not match!", "danger")
        return redirect(url_for('my_account'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 2. Fetch current password hash to verify identity
        cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            stored_hash = user['password']
            
            # 3. Verify the OLD password
            if check_password_hash(stored_hash, current_pass):
                
                # 4. Hash the NEW password
                new_hash = generate_password_hash(new_pass)
                
                # 5. Update Database
                update_query = "UPDATE users SET password = %s WHERE id = %s"
                cursor.execute(update_query, (new_hash, user_id))
                conn.commit()
                
                flash("Password changed successfully! Please log in again.", "success")
                
                # Optional: Logout user after password change for security
                # session.clear()
                # return redirect(url_for('login'))
                
            else:
                flash("Incorrect current password.", "danger")
        else:
            flash("User not found.", "danger")

    except Exception as e:
        print(f"Error: {e}")
        flash("An error occurred while changing password.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('my_account'))







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
