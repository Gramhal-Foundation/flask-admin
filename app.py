# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import pandas as pd
import csv
import io
import boto3, botocore
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# Change 'your_secret_key' to a strong and unique secret key
app.secret_key = 'randomsecret'

# PostgreSQL database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

# AWS S3 configurations
app.config['S3_BUCKET'] = os.getenv('S3_BUCKET')
app.config['S3_KEY'] = os.getenv('S3_KEY')
app.config['S3_SECRET'] = os.getenv('S3_SECRET')
app.config['S3_REGION'] = os.getenv('S3_REGION')
app.config['S3_LOCATION'] = 'https://' + os.getenv('S3_BUCKET') + '.s3.' + os.getenv('S3_REGION') + '.amazonaws.com/'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

s3 = boto3.client(
   "s3",
   aws_access_key_id=app.config['S3_KEY'],
   aws_secret_access_key=app.config['S3_SECRET']
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=True)
    phone = db.Column(db.String(80), nullable=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')


# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/user')
@login_required
def user_list():
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    users_pagination = User.query.order_by(User.id).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('user.html', users_pagination=users_pagination)

@app.route('/user/create', methods=['GET', 'POST'])
@login_required
def user_create():
    if request.method == 'GET':
        return render_template('user/create.html')

    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')

    new_user = User(name=name, email=email, phone=phone, password=password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('user_list'))

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    user = User.query.get(user_id)

    if not user:
        return redirect(url_for('user_list'))

    if request.method == 'GET':
        return render_template('user/edit.html', user=user)

    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    password = request.form.get('password')

    print('email...', email)
    print('user.email...', user.email)
    if email != user.email:
        user.email = email

    if password:
        user.password = password

    user.name = name
    user.phone = phone

    # new_user = User.query.update(name=name, email=email, phone=phone, password=password)
    # db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('user_list'))

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def user_delete(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('user_list'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and user.password == password:
            login_user(user)
            return redirect(url_for('user'))
        else:
            flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data

        # Check if the email is already taken
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        # Create a new user and add to the database
        new_user = User(email=email, password=password, name=name, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

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
                "ContentType": file.content_type    #Set appropriate content type as per the file
            }
        )
    except Exception as e:
        print("Something Happened: ", e)
        return e
    return "{}{}".format(app.config["S3_LOCATION"], file.filename)

@app.route("/upload", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        col_names = ['Name', 'Phone', 'Email']
        csvData = pd.read_csv(uploaded_file, usecols=col_names)

        for i,row in csvData.iterrows():
            new_user = User(email=row['Email'], name=row['Name'], phone=row['Phone'], password='gramhal')
            db.session.add(new_user)
            db.session.commit()

        if uploaded_file:
            uploaded_file.filename = secure_filename(uploaded_file.filename)
            print('before upload_file_to_s3...', uploaded_file)
            output = upload_file_to_s3(uploaded_file, app.config["S3_BUCKET"])
            print('output...', output)

        flash('All users uploaded!')
        return redirect(url_for('user'))
    return render_template('upload.html')

@app.route("/download", methods=['GET'])
def download_file():
    users = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    line = ['Email', 'Name', 'Phone']
    writer.writerow(line)
    for user in users:
        line = [user.email, user.name, user.phone]
        writer.writerow(line)
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=users.csv"})

if __name__ == '__main__':
    app.run(debug=True)
