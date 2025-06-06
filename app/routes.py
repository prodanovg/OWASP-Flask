from flask import render_template, redirect, request, url_for, session
from . import db
from .models import User
from flask import current_app as app
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import text




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        #fixed vulnerable to Cryptographic failures and Injection
        # user = User.query.filter_by(username=username).first()
        # if user and check_password_hash(user.password, password):
        #     session['username'] = user.username
        #     session['role'] = user.role
        #     return redirect(url_for('home'))
        
        #2,3
        #vulnerable to Cryptographic failures and Injection
        query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
        result = db.session.execute(query).mappings().fetchone()

        if result:
            session['username'] = result['username']
            session['role'] = result['role']
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Invalid credentials")


    return render_template('login.html')


@app.route('/')
def home():
    user = session.get('username', 'Guest')
    role = session.get('role', 'None')
    return render_template('index.html', user=user, role=role)

#Vulnerable to Broken Access
# @app.route('/admin')
# def admin():
#     return "Welcome to the admin panel! Anyone can see this."


#Fixed Vulnerable to Broken Access
@app.route('/admin')
def admin():
    if session.get("role") != "admin":
        return render_template('403.html'), 403
    return "Welcome to the admin panel!"


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')  

        from .models import User
        #Vulnerable
        new_user = User(username=username, password=password,role='user',email=email)

        #fixed vuln
        # hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        # new_user = User(username=username, password=hashed_password, role='user')
       
        
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/view_users')
def view_users():
    user = session.get('username', 'Guest')
    users = User.query.all()
    return render_template('view_users.html', user=user,users=users)

@app.route('/api/users')
def api_users():
    users = User.query.all()
    users_data = [
        {"username": user.username, "password": user.password, "role": user.role, "email": user.email}
        for user in users
    ]
    return {"users": users_data}

@app.after_request
def add_csp_headers(response):
    response.headers['Content-Security-Policy'] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
    return response


@app.route('/update_profile/<int:user_id>', methods=['GET', 'POST'])
def update_profile(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_to_update = User.query.get(user_id)
    # if not user_to_update:
    #     return "User not found", 404
    user_to_update.email 
    
    # logged_in_user = User.query.filter_by(username=session['username']).first()
    # if logged_in_user.role != 'admin' and logged_in_user.id != user_id:
    #     return render_template('403.html'), 403

    if request.method == 'POST':
        new_email = request.form.get('email')
        user_to_update.email = new_email
        db.session.commit()
        return redirect(url_for('view_users'))

    return render_template('update_profile.html', user=user_to_update)
