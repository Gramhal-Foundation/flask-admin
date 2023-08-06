from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from . import admin

# fix this hardcoded line
from models.user import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@admin.route('/')
@login_required
def default():
    return 'hello there admin'

@admin.route('/reports')
@login_required
def reports():
    return 'hello there admin reporting page is here....'

@admin.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # if form.validate_on_submit():
    #     email = form.email.data
    #     password = form.password.data

    #     user = User.query.filter_by(email=email).first()

    #     if user and user.password == password:
    #         login_user(user)
    #         return redirect(url_for('user'))
    #     else:
    #         flash('Invalid credentials. Please try again.', 'error')

    return render_template('login.html', form=form)
