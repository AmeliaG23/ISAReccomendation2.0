"""
File : app.py
Author : Amelia Goldsby
Date Created : 21/08/2024
Project : ISA Recommendation Website
Course : Software Engineering and DevOps, 
         Level 6, QA 

Description : This file is the main basis for the whole ISA Recommendation Website, 
              and contains the main functionalities, like configrations of the app routes, 
              and creation of the database isaDetails.db. CRUD operations are defined here, 
              allowing regular users to create, read, and update, and admin users to complete 
              the ssme operations, as well as delete.
"""

#Imports neccessary for all app route functionalities to work
from sqlite3 import IntegrityError
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import re

# Initialize the Flask application
app = Flask(__name__)

# Configuration for Database location and secret key for sessions
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'isa.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy database object
db = SQLAlchemy(app)
app.app_context().push()

# ISARecommendations.db Tables (Becker, 2023)
# Defines User model for db
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f'<User {self.username}>'

# Defines Projections model for db
class Projections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deposit = db.Column(db.Float, nullable=False)
    monthlyPayment = db.Column(db.Float, nullable=False)
    years = db.Column(db.Integer, nullable=False)
    savings = db.Column(db.Boolean, nullable=False)
    highDebt = db.Column(db.Boolean, nullable=False)
    changes = db.Column(db.Boolean, nullable=False)
    riskRatingCount = db.Column(db.Integer, nullable=False)
    riskRating = db.Column(db.String(20), nullable=False)
    projectionAmount = db.Column(db.Float, nullable=True)
    projectionRiskAmount = db.Column(db.Float, nullable=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define relationship between User and Projections
    user = db.relationship('User', backref=db.backref('projections', lazy=True))

    def __repr__(self) -> str:
        return f'<Projections {self.id}>'

# Function to validate username
def validateUsername(username):
    errors = []
    if not username:
        errors.append("Username cannot be empty.")
    if len(username) < 5 or len(username) > 15:
        errors.append("Username must be between 5 and 15 characters long.")
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        errors.append("Username already exists.")
    return errors

# Function to validate password - checks length and for special characters
def validatePassword(password):
    errors = []
    if not password:
        errors.append("Password cannot be empty.")
    if len(password) < 6 or len(password) > 14:
        errors.append("Password must be between 6 and 14 characters long.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character.")
    return errors


# Function to retrieve the current logged-in user ID
def getCurrentUser():
    if 'userId' in session:
        userId = session['userId']
        user = db.session.get(User, userId)
        if user:
            return user.id  # Return only the user ID
    return None

# Function to hash the password using bcrypt
def hashPassword(password):
    salt = bcrypt.gensalt()  # Generate a salt
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password with the salt
    return hashed.decode('utf-8')  # Return as a UTF-8 string

# Function to check the password
def checkPassword(hashedPassword, inputPassword):
    return bcrypt.checkpw(inputPassword.encode('utf-8'), hashedPassword.encode('utf-8'))


# Function to calculate future value based on inputs
def calculateFutureValue(deposit, monthlyPayment, years, annualAer):
    monthlyAer = (1 + annualAer) ** (1 / 12) - 1 # Calculate monthly Aer from annual rate
    totalMonths = years * 12
    futureDeposit = deposit * (1 + annualAer) ** years
    futureMonthlyPayments = monthlyPayment * (((1 + monthlyAer) ** totalMonths - 1) / monthlyAer)
    return round(futureDeposit + futureMonthlyPayments, 2)

# Function to determine the Aer based on risk tolerance
def getRiskAer(riskTolerance):
    if riskTolerance == 'low':
        return 0.0408
    elif riskTolerance == 'medium':
        return 0.0529
    elif riskTolerance == 'high':
        return 0.1158
    else:
        return 0.0484 # Default value

# Calculate a risk rating count based answers from fact find form
def calculateRiskRatingCount(riskTolerance, investmentComfort, investmentReview):
    riskRatingCount = 0 # Defualt Value
    # Increment count based on risk tolerance
    if riskTolerance == 'high':
        riskRatingCount += 3
    elif riskTolerance == 'medium':
        riskRatingCount += 2
    else:  # 'low'
        riskRatingCount += 1

    # Increment count based on comfort level
    if investmentComfort == 'veryComfortable':
        riskRatingCount += 3
    elif investmentComfort == 'somewhatComfortable':
        riskRatingCount += 2
    else:  # 'notComfortable'
        riskRatingCount += 1

    # Increment count based on investment review frequency
    if investmentReview == 'regularly':
        riskRatingCount += 3
    elif investmentReview == 'occasionally':
        riskRatingCount += 2
    else:  # 'rarely'
        riskRatingCount += 1

    return riskRatingCount

# Function to add initial data to the database (2 admin users + 8 regular users)
def initializeData():
    try:
        with app.app_context():
            # Check if any users exist in the database
            if User.query.first() is not None:
                print("Data already initialized.")
            else:
                # Define 2 admin users and 8 regular users
                adminUsers = [
                    {'username': 'admin1', 'password': 'admin_password1'},
                    {'username': 'admin2', 'password': 'admin_password2'}
                ]
                regularUsers = [
                    {'username': f'user{i}', 'password': f'user{i}_password'} for i in range(1, 9)
                ]

                # Add users to the database
                for user_data in adminUsers:
                    if not User.query.filter_by(username=user_data['username']).first():
                        hashed_password = hashPassword(user_data['password'])
                        new_user = User(
                            username=user_data['username'],
                            password=hashed_password,
                            admin=True
                        )
                        db.session.add(new_user)

                for user_data in regularUsers:
                    if not User.query.filter_by(username=user_data['username']).first():
                        hashed_password = hashPassword(user_data['password'])
                        new_user = User(
                            username=user_data['username'],
                            password=hashed_password,
                            admin=False
                        )
                        db.session.add(new_user)

                db.session.commit()  # Commit users to the database

                # Retrieve all users from the database
                allUsers = User.query.all()

                # Define values for projections
                deposit = 1000.0
                monthlyPayment = 50.0
                years = 10

                # Add projections for each user
                for user in allUsers:
                    if not Projections.query.filter_by(userId=user.id).first():
                        # Calculate future value of savings
                        annualAer = 0.0484  # Default AER
                        riskAer = getRiskAer('medium')  # Example risk rating
                        
                        projectionAmount = calculateFutureValue(deposit, monthlyPayment, years, annualAer)
                        projectionRiskAmount = calculateFutureValue(deposit, monthlyPayment, years, riskAer)
                        
                        # Create new projection
                        projection = Projections(
                            deposit=deposit,
                            monthlyPayment=monthlyPayment,
                            years=years,
                            savings=True,
                            highDebt=False,
                            changes=False,
                            riskRating='medium',
                            riskRatingCount=calculateRiskRatingCount('medium', 'veryComfortable', 'regularly'),
                            projectionAmount=projectionAmount,
                            projectionRiskAmount=projectionRiskAmount,
                            userId=user.id
                        )
                        db.session.add(projection)

                db.session.commit()  # Commit projections to the database

                print("Data initialization complete.")

    except IntegrityError:
        db.session.rollback()
        print("Error adding data. Some entries might already exist.")
    except Exception as e:
        db.session.rollback()
        print(f"An unexpected error occurred: {e}")

# Default route which is user login
@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and checkPassword(user.password, password):  # Check hashed password
            session['userId'] = user.id
            session['admin'] = user.admin
            return redirect(url_for('home'))
        else:
            return render_template('index.html', error="Invalid credentials")

    return render_template('index.html')

# Route for sign up
@app.route('/signUp', methods=['GET', 'POST'])
def signUp():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirmPassword = request.form['confirm_password']

         # Validate username
        usernameError = validateUsername(username)
        if usernameError:
            flash(usernameError, 'warning')
            return redirect(url_for('signUp'))

        # Validate password
        passwordError = validatePassword(password)
        if passwordError:
            flash(passwordError, 'warning')
            return redirect(url_for('signUp'))

        # Check if passwords match
        if password != confirmPassword:
            flash("Passwords do not match", 'warning')
            return redirect(url_for('signUp'))
        
        hashedPassword = hashPassword(password)  # Hash the password
        newUser = User(username=username, password=hashedPassword, admin=False)
        #(Python Tutorials, 2023)

        try:
            db.session.add(newUser)
            db.session.commit()

            return redirect(url_for('signUp', success=True))
        except:
            # Warning error if username already exists
            flash("Username already exists", 'warning')
            return redirect(url_for('signUp'))

    return render_template('signUp.html')

# Route for home page- accessible once user has logged in
@app.route('/home', methods=['GET'])
def home():
    user = getCurrentUser()
    if user:
        return render_template('home.html', admin=session.get('admin'), user=user)
    else:
        flash("You must log in to access this page.", "error")
        return redirect(url_for('index'))

# Route for the admin page - admin users can perform CRUD operations on user details
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check if the user is logged in and has admin privileges
    if 'userId' in session and session.get('admin'):
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            # Convert the 'admin' radio button value to a boolean
            admin = request.form.get('admin') == 'yes'

           # Validate username
            usernameErrors = validateUsername(username)
            if usernameErrors:
                for error in usernameErrors:
                    flash(error, 'warning')
                return render_template('admin.html', users=User.query.all())

            # Validate password
            passwordErrors = validatePassword(password)
            if passwordErrors:
                for error in passwordErrors:
                    flash(error, 'warning')
                return render_template('admin.html', users=User.query.all())
            # Hash the password before storing it
            hashedPassword = hashPassword(password)

            # Create a new User object
            newUser = User(username=username, password=hashedPassword, admin=admin)

            try:
                # Commit new User object
                db.session.add(newUser)
                db.session.commit()
                flash("User added successfully", 'success')
            except Exception as e:
                # Handle any exceptions
                print(f"Error: {e}")
                flash("An error occurred while adding the user", 'danger')

        # Retrieve all users from the database to display on the page
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        # If the user is not logged in or is not an admin, redirect to the login page
        return redirect(url_for('index'))


# Route for admin accounts to access table to view all user account and perform CRUD operations
@app.route('/userAccount', defaults={'id': None}, methods=['GET', 'POST'])
@app.route('/userAccount/<int:id>', methods=['GET', 'POST'])
def userAccount(id):
    # Get the currently logged-in user ID from the session
    currentUserId = getCurrentUser()

    if currentUserId:
        if id is None:  # If no specific ID is provided, assume the current user's ID
            id = currentUserId

        # Fetch the user object from the database
        user = User.query.get_or_404(id)

        if request.method == 'POST':
            # Retrieve the new username and password from the form
            newUsername = request.form.get('username', '').strip()
            newPassword = request.form.get('password', '').strip()

            # Check if a new username is provided and if it's different from the current username
            if newUsername and newUsername != user.username:
                # Validate new username
                usernameErrors = validateUsername(newUsername)
                if usernameErrors:
                    for error in usernameErrors:
                        flash(error, 'warning')
                    return render_template('userAccount.html', user=user)
                
                # Check if the new username is already in use by another user
                existingUser = User.query.filter_by(username=newUsername).first()
                if existingUser and existingUser.id != user.id:
                    flash("Username is already in use. Please choose a different one.", 'warning')
                    return render_template('userAccount.html', user=user)

                # Update username
                user.username = newUsername

            if newPassword:
                # Validate password if provided
                passwordErrors = validatePassword(newPassword)
                if passwordErrors:
                    for error in passwordErrors:
                        flash(error, 'warning')
                    return render_template('userAccount.html', user=user)
                
                # Hash the new password before saving
                hashedPassword = hashPassword(newPassword)
                user.password = hashedPassword

            try:
                db.session.commit()
                flash("Account updated successfully!", 'success')
                return redirect(url_for('userAccount', id=user.id))
            except Exception as e:
                print(f"Error: {e}")
                flash("An error occurred while updating the account", 'danger')

        return render_template('userAccount.html', user=user, previousPage='home')

    else:
        return redirect(url_for('index'))
    # (TRCCompSci, 2019)

# Route for admin deleting user from User table
@app.route('/delete/<int:id>')
def delete(id):
    # id of chosen user is passed through and retrieved
    userToDelete = User.query.get_or_404(id) 
    try:
        # Deletes user
        Projections.query.filter_by(userId=id).delete()
        db.session.delete(userToDelete)
        db.session.commit()
        
        return redirect(url_for('admin'))
    
    # Handles exception
    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()  
        return 'Error with deleting user'

# Route for admin updating user details from Admin Control Page
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        # Retrieve the new username and password from the form
        newUsername = request.form.get('username', '').strip()
        newPassword = request.form.get('password', '').strip()

        # Check if a new username is provided and if it's different from the current username
        if newUsername and newUsername != user.username:
            # Validate new username
            username_errors = validateUsername(newUsername)
            if username_errors:
                for error in username_errors:
                    flash(error, 'warning')
                return render_template('userAccount.html', user=user)

            # Check if the new username is already in use by another user
            existing_user = User.query.filter_by(username=newUsername).first()
            if existing_user and existing_user.id != user.id:
                flash("Username already exists", 'warning')
                return render_template('userAccount.html', user=user)
            
            # Update username
            user.username = newUsername

        # Validate and update password if provided
        if newPassword:
            password_errors = validatePassword(newPassword)
            if password_errors:
                for error in password_errors:
                    flash(error, 'warning')
                return render_template('userAccount.html', user=user)
            # Hash the new password before saving
            hashed_password = hashPassword(newPassword)
            user.password = hashed_password
         
        try:
            db.session.commit()
            flash("Account updated successfully", 'success')
        except Exception as e:
            print(f"Error: {e}")
            flash("An error occurred while updating the account", 'danger')

    return render_template('userAccount.html', user=user, previousPage= 'admin')


# Route for user to log out of application
@app.route('/logout')
def logout():
    session.pop('userId', None)
    session.pop('admin', None)
    # Redirects to log in page
    return redirect(url_for('index'))

# Route for fact find where users complete form for projections
@app.route('/factFind/', methods=['GET', 'POST'])
def factFind():
    user = getCurrentUser()  # Get the current user
    if not user:
        # Redirect to the login page if no user is authenticated
        return redirect(url_for('index'))

    userId = session.get('userId')
    if userId is None:
        return redirect(url_for('index'))

    # Prepare pre-filled form data with default empty values
    prefilledData = {
        'deposit': '',
        'monthlyPayment': '',
        'years': '',
        'savings': '',
        'highDebt': '',
        'changes': '',
    }

    # Check if the user came from the recommendations page
    came_from_recommendations = session.pop('came_from_recommendations', False)

    # Retrieve existing projection for the user only if they came from recommendations
    if came_from_recommendations:
        projections = Projections.query.filter_by(userId=userId).first()
        if projections:
            prefilledData = {
                'deposit': projections.deposit,
                'monthlyPayment': projections.monthlyPayment,
                'years': projections.years,
                'savings': 'true' if projections.savings else 'false',
                'highDebt': 'true' if projections.highDebt else 'false',
                'changes': 'true' if projections.changes else 'false',
            }

    if request.method == 'POST':
        try:
            # Retrieve all form data from the request
            deposit = request.form.get('deposit')
            monthlyPayment = request.form.get('monthlyPayment')
            years = request.form.get('years')
            savings = request.form.get('savings') == 'true'
            highDebt = request.form.get('highDebt') == 'true'
            changes = request.form.get('changes') == 'true'
            riskTolerance = request.form.get('riskTolerance')
            investmentComfort = request.form.get('investmentComfort')
            investmentReview = request.form.get('investmentReview')

            # Ensure that all fields have been filled out
            if not all([deposit, monthlyPayment, years, savings is not None, highDebt is not None, changes is not None, riskTolerance, investmentComfort, investmentReview]):
                return render_template('factFind.html', error="All fields must be filled out", prefilledData=prefilledData)

            # Convert to requested data types matching table layout
            deposit = float(deposit)
            monthlyPayment = float(monthlyPayment)
            years = int(years)

            # Calculate the attitude to risk score count
            riskRatingCount = calculateRiskRatingCount(riskTolerance, investmentComfort, investmentReview)

            # Checks if there is an existing projection for the current user
            projections = Projections.query.filter_by(userId=userId).first()
            if projections:
                projections.deposit = deposit
                projections.monthlyPayment = monthlyPayment
                projections.years = years
                projections.savings = savings
                projections.highDebt = highDebt
                projections.changes = changes
            else:
                projections = Projections(
                    deposit=deposit,
                    monthlyPayment=monthlyPayment,
                    years=years,
                    savings=savings,
                    highDebt=highDebt,
                    changes=changes,
                    riskRating=riskTolerance,
                    riskRatingCount=riskRatingCount,
                    userId=userId
                )
                db.session.add(projections)

            # Calculate future values for projections
            annualAer = 0.0484  # Default annual AER
            futureValue = calculateFutureValue(deposit, monthlyPayment, years, annualAer)
            riskAer = getRiskAer(riskTolerance)  # Get AER based on the user's risk attitude
            futureValueRisk = calculateFutureValue(deposit, monthlyPayment, years, riskAer)

            # Update projection amounts in the projections record
            projections.projectionAmount = futureValue
            projections.projectionRiskAmount = futureValueRisk
            db.session.commit()

            return redirect(url_for('projection'))

        except Exception as e:
            print(f"Error: {e}")
            return render_template('factFind.html', error="An error occurred while saving your data.", prefilledData=prefilledData)

    return render_template('factFind.html', prefilledData=prefilledData)

# Route for projection which displays projection amount after fact find form completed
@app.route('/projection')
def projection():
    # Displays projection for current user
    userId = getCurrentUser()
    if userId:
        projection = Projections.query.filter_by(userId=userId).first()
        if projection:
            return render_template(
                'projection.html',
                deposit=projection.deposit,
                monthlyPayment=projection.monthlyPayment,
                years=projection.years,
                projectionAmount=projection.projectionAmount,
                projectionRiskAmount=projection.projectionRiskAmount,
                riskRating=projection.riskRating
            )
    return render_template('projection.html', error="Projection data not available")

# Route for recommendations which displays recent projection for current user
@app.route('/recommendations')
def recommendations():
    user = getCurrentUser()
    if user:
        userId = session['userId']
        
        # Track that the user came from the recommendations page
        session['came_from_recommendations'] = True

        # Fetch Projections for the current user
        projectionsData = Projections.query.filter_by(userId=userId).all()

        # Pass data to the template
        return render_template('recommendations.html', projectionsData=projectionsData)
    else:
        return redirect(url_for('index'))


# Entry point for the application
if __name__ == '__main__':
    initializeData()
    app.run()

#(Jakerieger, 2022)