from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from . import admin
from admin_views import *

# fix this hardcoded line
from models.user import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@admin.route('/')
@login_required
def index():
    return redirect(url_for('.dashboard'))

@admin.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@admin.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # email/username/phone & password to be picked from app config
        # to understand the primary field names and avoid conflicts
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(phone_number=email).first()

        if user and user.password == password:
            login_user(user)
            return redirect(url_for('.dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html', form=form)

@admin.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('.login'))

@admin.route('/resource/<string:resource>')
@login_required
def resource(resource):
    resource_class = globals()[resource.capitalize() + "Admin"]
    model = resource_class.model
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    pagination = model.query.paginate(page=page, per_page=per_page, error_out=False)
    list_display = resource_class.list_display
    return render_template('user/list.html', pagination=pagination, resource=resource, list_display=list_display)
