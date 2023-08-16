"""
app.py: Main module for the Flask application.

This module initializes the Flask application and sets up various components
such as the database, login manager, and routes for user management.

Dependencies:
    - Flask
    - flask_sqlalchemy
    - flask_migrate
    - flask_login
    - flask_wtf
    - wtforms
    - pandas
    - boto3
    - werkzeug
    - dotenv

Usage:
    Run this script to start the Flask application.
"""
import csv
import io
import os
import boto3
from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import pandas as pd
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Change 'your_secret_key' to a strong and unique secret key
app.secret_key = "randomsecret"

# PostgreSQL database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv(
    "SQLALCHEMY_TRACK_MODIFICATIONS"
)

# AWS S3 configurations
app.config["S3_BUCKET"] = os.getenv("S3_BUCKET")
app.config["S3_KEY"] = os.getenv("S3_KEY")
app.config["S3_SECRET"] = os.getenv("S3_SECRET")
app.config["S3_REGION"] = os.getenv("S3_REGION")
app.config["S3_LOCATION"] = (
    "https://"
    + os.getenv("S3_BUCKET")
    + ".s3."
    + os.getenv("S3_REGION")
    + ".amazonaws.com/"
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

s3 = boto3.client(
    "s3",
    aws_access_key_id=app.config["S3_KEY"],
    aws_secret_access_key=app.config["S3_SECRET"],
)


class User(UserMixin, db.Model):
    """
    Represents a user in the application.

    Attributes:
        id (int): The unique identifier for the user.
        email (str): The email address of the user.
        name (str): The name of the user.
        phone (str): The phone number of the user.
        password (str): The user's password.
        role (str): The role of the user.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=True)
    phone = db.Column(db.String(80), nullable=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")


# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user by their ID.

    This function is used by Flask-Login to load a user object based on
    their user ID.

    Args:
        user_id (int): The ID of the user to load.

    Returns:
        User: The User object corresponding to the given user ID,
        or None if not found.
    """
    return User.query.get(int(user_id))


class RegistrationForm(FlaskForm):
    """
    Form for user registration.

    Attributes:
        name (StringField): Field for entering the user's name.
        email (StringField): Field for entering the user's email address.
        phone (StringField): Field for entering the user's phone number.
        password (PasswordField): Field for entering the user's password.
        confirm_password (PasswordField): Field for confirming the
        user's password.
        submit (SubmitField): Button to submit the registration form.
    """
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    phone = StringField("Phone", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    """
    Form for user login.

    Attributes:
        email (StringField): Field for entering the user's email address.
        password (PasswordField): Field for entering the user's password.
        submit (SubmitField): Button to submit the login form.
    """
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route("/user")
@login_required
def user_list():
    """
    Display a paginated list of users.

    Returns:
        Response: Rendered HTML template displaying user list.
    """
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    users_pagination = User.query.order_by(User.id).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("user/list.html", users_pagination=users_pagination)


@app.route("/user/create", methods=["GET", "POST"])
@login_required
def user_create():
    """
    Handle user creation.

    Returns:
        Response: Redirects to user list or renders user creation form.
    """
    if request.method == "GET":
        return render_template("user/create.html")

    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    password = request.form.get("password")

    new_user = User(name=name, email=email, phone=phone, password=password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for("user_list"))


@app.route("/user/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(user_id):
    """
    Edit user details.

    Allows users to edit their details. Handles both GET and POST requests.

    Args:
        user_id (int): The ID of the user to edit.

    Returns:
        Response: Redirects to the user list page after successful edit.
    """
    user = User.query.get(user_id)

    if not user:
        return redirect(url_for("user_list"))

    if request.method == "GET":
        return render_template("user/edit.html", user=user)

    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    password = request.form.get("password")

    print("email...", email)
    print("user.email...", user.email)
    if email != user.email:
        user.email = email

    if password:
        user.password = password

    user.name = name
    user.phone = phone

    db.session.commit()

    return redirect(url_for("user_list"))


@app.route("/user/delete/<int:user_id>", methods=["POST"])
@login_required
def user_delete(user_id):
    """
    Delete a user.

    Handles user deletion when a POST request is received.

    Args:
        user_id (int): The ID of the user to delete.

    Returns:
        Response: Redirects to the user list page after successful deletion.
    """
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for("user_list"))


@app.route("/logout")
@login_required
def logout():
    """
    Log out a user.

    Returns:
        Response: Redirects to the login page after successfully logging out.
    """
    logout_user()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login.

    Handles user login. Displays the login form for GET requests and
    processes the form for POST requests.

    Returns:
        Response: Redirects to the user page after successful login, or
        renders the login form on error.
    """
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and user.password == password:
            login_user(user)
            return redirect(url_for("user"))
        else:
            flash("Invalid credentials. Please try again.", "error")

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    User registration.

    Handles user registration. Displays the registration form for GET requests
    and processes the form for POST requests.

    Returns:
        Response: Redirects to the login page after successful registration, or
        renders the registration form on error.
    """
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data

        # Check if the email is already taken
        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please choose a different one.",
                  "error")
            return redirect(url_for("register"))

        # Create a new user and add to the database
        new_user = User(email=email, password=password, name=name, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


def upload_file_to_s3(file, bucket_name, acl="public-read"):
    """
    Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
    """
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type,
            },
        )
    except Exception as exception:
        error_message = f"Something Happened: {exception}"
        print(error_message)
        return error_message
    return f"{app.config['S3_LOCATION']}{file.filename}"


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """
    Upload a CSV file of users.

    Handles file upload for user creation.

    Returns:
        Response: Redirects to the user list page after successful upload.
    """
    if request.method == "POST":
        uploaded_file = request.files["file"]
        col_names = ["Name", "Phone", "Email"]
        csv_data = pd.read_csv(uploaded_file, usecols=col_names)

        for row in csv_data.iterrows():
            new_user = User(
                email=row["Email"],
                name=row["Name"],
                phone=row["Phone"],
                password="gramhal",
            )
            db.session.add(new_user)
            db.session.commit()

        if uploaded_file:
            uploaded_file.filename = secure_filename(uploaded_file.filename)
            print("before upload_file_to_s3...", uploaded_file)
            output = upload_file_to_s3(uploaded_file, app.config["S3_BUCKET"])
            print("output...", output)

        flash("All users uploaded!")
        return redirect(url_for("user"))
    return render_template("upload.html")


@app.route("/download", methods=["GET"])
@login_required
def download_file():
    """
    Download user data as a CSV file.

    Retrieves user data from the database and generates a CSV file for
    download.

    Returns:
        Response: CSV file response with appropriate headers for download.
    """
    users = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    line = ["Email", "Name", "Phone"]
    writer.writerow(line)
    for user in users:
        line = [user.email, user.name, user.phone]
        writer.writerow(line)
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=users.csv"},
    )


@app.route("/reports")
@login_required
def reports():
    """
    Display user reports.

    Returns:
        Response: Rendered HTML template displaying user reports.
    """
    return render_template("reports.html")


if __name__ == "__main__":
    app.run(debug=True)
