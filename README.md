# ISA Recommendation Website

This website creates a Projection prediction for ISAs (Individual Savings Account) for users by proviing a fact find evalution form which measures a user's affordability and attitude to risk, to then calculate relevant projection details.

# Table of Contents

1. [Project Description](#project-description)
2. [Key Features](#key-features)
3. [Technologies Used](#technologies-used)
4. [CI/CD Pipeline](#cicd-pipeline)
5. [Prerequisites](#prerequisites)
6. [Installation Steps](#installation-steps)
7. [Authors](#authors)
8. [Version History](#version-history)
9. [Acknowledgments](#acknowledgments)

## Project Description

**The ISA Recommendation Website** is an application which has been created for Aviva. The main function is to allow users to receive a projection prediction, rather than calling customer advisors at Aviva. This has shown to be a major contributing factor into creating a high average call time for users through research. Removing the need for customer advisors completing this journey for users, allows reduced average call times for customers, but also less calls relating to ISA recommendations.

Users are able to log in to the application and complete the Fact Find form, to analyse affordability and their attitude to risk. Two projections are produced to the user, once the form is complete:

- **Normal Projection:** Projection against average savings rate (29/08/2024) against total over years.
- **Risk Projection:** Projection against rate analysed from risk attitude (29/08/2024)

Past projections are visible to users, if the fact find evaluation has been completed, from the home page. Users have the ability to change their username and password.

Admin users have the ability to perform all **CRUD** operations (CREATE, READ, UPDATE, DELETE), as they have access to the database holding user details (User table). They can read all users, add users, update user details, and delete users.

The website has been deployed using [Render.com](https://render.com) and can be accessed here:  
👉 [ISA Recommendation Website on Render](https://isarecomendation2-0.onrender.com)

## Key Features

- **User Log In and Sign Up:** Secure login and signup functionality with password hashing.
- **Account Management:** Users can update their account details including usernames and passwords.
- **Administrative Controls:** Admin users can create, update, and delete user accounts.
- **Responsive Design:** User-friendly and responsive interface for various devices.
- **Recommendation Journey:** Easy form analysing risk attitude and affordability. A projection is produced from this
- **Projection View**: Past projection prediction for user can be viewed from home screen.
- **Simple Navigation:** Pages are labelled with back and continue buttons. The title in the header also, when clicked, navigates user back to home screen.
- **Validation:** All user input sections have validation, for example: the username and password for users must be between 5 to 15 characters

## Technologies Used

- **Flask**: Python web framework for building web applications.
- **SQLAlchemy**: ORM for managing database interactions.
- **Bootstrap**: CSS framework for responsive and modern design.
- **Jinja2**: Templating engine for rendering HTML templates.

## CI/CD Pipeline

This project uses **GitHub Actions** for Continuous Integration and Deployment (CI/CD). On every push to the `main` branch:

1. All dependencies are installed.
2. Automated tests are run using `pytest`.
3. If tests pass, the app is deployed to [Render](https://render.com) using their REST API.

Secrets like `RENDER_DEPLOY_HOOK` are securely stored in GitHub repository settings.

### Prerequisites

- Python 3.10
- Flask
- SQLAlchemy
- Pytest
- Dependencies listed in `requirements.txt`

### Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/AmeliaG23/ISA-Recommendation-Website.git
   cd your-repo
   ```
2. **Create Virtual Environment:**:

   ```bash
   python -m venv venv
   ```

3. **Activate Virtual Environment**

   - Windows:

   ```bash
   env\Scripts\activate
   ```

   - Mac OS:

   ```bash
   source env/bin/activate
   ```

4. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

5. **Ensure Packages are up-to-date**

   ```bash
   pip audit
   ```

   **IMPORTANT- Please update any vulnerabilities to protect the application against Dependency Vulnerabilities**

6. **Setup Database**

   SQLAlchemy and Python3 was used for this program, and created by:

   ```bash
   python3
   from app import db
   db.create_all()
   exit()
   ```

7. **Run Application**
   ```bash
   python3 app.py
   ```

## Usage

When the above steps have been completed navigate to http://localhost:5000 in your web browser to use the application. To access an admin account please use these details:

- username: **admin1**
- password: **admin_password1**
  OR
- username: **admin2**
- password: **admin_password2**

To access a regular user account please sign up

## Authors

Amelia Goldsby

## Version History

- 0.1

  - Initial Release

## Acknowledgments

**Code snippets:**

- [Jake Rieger Flask App](https://github.com/jakerieger/FlaskIntroduction)
- [W3Schools Form Validation](https://www.w3schools.com/js/js_validation.asp)
- [Python Password Hashing](https://pythonprogramming.net/password-hashing-flask-tutorial/)
- [Database Relationships](https://medium.com/@beckerjustin3537/creating-a-many-to-many-relationship-with-flask-sqlalchemy-69018d467d36)
- [README.md Layout](https://gist.github.com/DomPizzie/7a5ff55ffa9081f2de27c315f5018afc)

**Icons:**

- [Account icons created by Adrly](https://www.flaticon.com/free-icons/account)
- [Setting icons created by Ardly](https://www.flaticon.com/free-icons/setting)

**AER Rates:**

- [Savings Rate](https://www.money.co.uk/savings-accounts)
- [Risk Wizard](https://www.cushon.co.uk/riskwizard)

(README-Template, 2024)
