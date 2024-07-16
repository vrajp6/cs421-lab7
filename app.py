from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initializing the Flask application
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initializing the SQLAlchemy extension
db = SQLAlchemy(app)

# Defining the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

# Creating database tables before the first request
@app.before_first_request
def create_tables():
    db.create_all()

# Function to validate the mentioned passwrord requirements
def validate_password(password):
    errors = []
    if not any(c.islower() for c in password):
        errors.append("You did not use a lowercase character.")
    if not any(c.isupper() for c in password):
        errors.append("You did not use an uppercase character.")
    if not any(c.isdigit() for c in password):
        errors.append("You did not use a digit.")
    if len(password) < 8:
        errors.append("Your password must be at least 8 characters long.")
    return errors

# Route for the home page (takes you to the login page)
@app.route('/')
def index():
    return redirect(url_for('login'))

# Route for handling the login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))
        else:
            flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html')

# Route for handling the signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))
        
        errors = validate_password(password)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('signup'))
        # Bonus: Checking the db if the email is already registered
        if User.query.filter_by(email=email).first():
            flash('Email is already registered.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        session.clear()  # Making sure that the session is cleared after sign up
        return redirect(url_for('thankyou'))
    return render_template('signup.html')

# Route for the thank you page
@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

# Route for the secret page
@app.route('/secretPage')
def secret_page():
    if 'user_id' in session:
        return render_template('secretPage.html')
    else:
        flash('You need to be logged in to view this page.', 'danger')
        return redirect(url_for('login'))

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
