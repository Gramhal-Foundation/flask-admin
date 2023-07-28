# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import pandas as pd

app = Flask(__name__)

# Change 'your_secret_key' to a strong and unique secret key
app.secret_key = 'randomsecret'

# PostgreSQL database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres@localhost/testing'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')


# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/user')
@app.route('/user/<int:page>')
@login_required
def user(page=1):
    per_page = 5
    users_pagination = User.query.order_by(User.id).paginate(page=page, per_page=per_page, error_out=False)
    title = 'Flask App with Jinja2'
    name = 'Admin Panel'
    return render_template('user.html', title=title, name=name, users_pagination=users_pagination)

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
        email = form.email.data
        password = form.password.data

        # Check if the email is already taken
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        # Create a new user and add to the database
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route("/upload", methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        # uploaded_file.save() # save to s3
        col_names = ['Name', 'Phone', 'Email']
        csvData = pd.read_csv(uploaded_file, usecols=col_names)
        for i,row in csvData.iterrows():
            new_user = User(email=row['Email'], password='gramhal')
            db.session.add(new_user)
            db.session.commit()
        flash('All users uploaded!')
        return redirect(url_for('user'))
    return render_template('upload.html')

@app.route("/download", methods=['GET'])
def download_file():
    return 'hello'
    # return excel.make_response_from_array([[1, 2], [3, 4]], "csv")

@app.route("/export", methods=['GET'])
def export_records():
    return 'hello1123'
    # return excel.make_response_from_array([[1, 2], [3, 4]], "csv",
    #                                       file_name="export_data")

if __name__ == '__main__':
    app.run(debug=True)
