from flask import Flask, render_template as real_render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from . import admin
from admin_view import *
import ast

def get_class_names(file_path):
    with open(file_path, 'r') as file:
        file_content = file.read()

    class_names = []

    # Parse the Python code into an abstract syntax tree (AST)
    tree = ast.parse(file_content)

    # Traverse the AST and extract class names
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_names.append(node.name)

    return class_names

def render_template(*args, **kwargs):
    class_names = get_class_names('admin_view.py')
    class_names.remove('FlaskAdmin')
    resource_types = [globals()[x].model.__name__.lower() for x in class_names]
    print('resource_types...', resource_types)
    return real_render_template(*args, **kwargs, resource_types=resource_types)

# [TODO]: dependency on main repo
from db import db

# [TODO]: fix this hardcoded line
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

@admin.route('/resource/<string:resource_type>')
@login_required
def resource_list(resource_type):
    resource_class = globals()[resource_type.capitalize() + "Admin"]
    model = resource_class.model
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    primary_key_column = model.__table__.primary_key.columns.keys()[0]
    pagination = model.query.order_by(primary_key_column).paginate(page=page, per_page=per_page, error_out=False)
    list_display = resource_class.list_display
    return render_template('resource/list.html', pagination=pagination, resource_type=resource_type, list_display=list_display)

@admin.route('/resource/<string:resource_type>/<string:resource_id>/edit', methods=['GET', 'POST'])
@login_required
def resource_edit(resource_type, resource_id):
    resource_class = globals()[resource_type.capitalize() + "Admin"]
    model = resource_class.model
    resource = model.query.get(resource_id)

    if not resource:
        return redirect(url_for('.resource_list'))

    all_columns = model.__table__.columns.keys()
    primary_key_columns = model.__table__.primary_key.columns.keys()
    ignore_columns = ['created_at', 'updated_at'] + primary_key_columns

    editable_columns = []
    for column in all_columns:
        if column not in ignore_columns:
            editable_columns.append(column)

    if request.method == 'GET':
        return render_template('resource/edit.html', resource_type=resource_type, resource=resource, editable_columns=editable_columns)

    for column in editable_columns:
        # [TODO]: add data validation
        setattr(resource, column, request.form.get(column))

    db.session.commit()

    return redirect(url_for('.resource_list', resource_type=resource_type))
