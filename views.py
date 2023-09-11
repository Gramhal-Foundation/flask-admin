from flask import render_template as real_render_template, request, redirect, url_for, flash, Response
from flask_login import login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from . import admin
from admin_view import *
import ast
from datetime import datetime
from app import app
import csv
import io
import boto3
import pandas as pd
from werkzeug.utils import secure_filename
import string

# [TODO]: dependency on main repo
from db import db

# [TODO]: fix this hardcoded line
from models.user import UserModel as User

def upload_file_to_s3(file, bucket_name = '', acl="public-read"):
    """
    Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
    """
    if not app.config['S3_KEY']:
        return None

    if not bucket_name:
        bucket_name = app.config["S3_BUCKET"]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=app.config['S3_KEY'],
        aws_secret_access_key=app.config['S3_SECRET']
    )
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )
        return "{}{}".format(app.config["S3_LOCATION"], file.filename)
    except Exception as e:
        print("Something Happened: ", e)
        return e

@app.template_filter('admin_label_plural')
def admin_label_plural(label):
    import inflect
    p = inflect.engine()
    formatted_label = label.replace("-", " ")
    formatted_label = p.plural_noun(formatted_label)
    formatted_label = string.capwords(formatted_label)
    return formatted_label

@app.template_filter('admin_label_singular')
def admin_label_singular(label):
    formatted_label = label.replace("-", " ")
    formatted_label = string.capwords(formatted_label)
    return formatted_label

@app.template_filter('admin_format_datetime')
def admin_format_datetime(value):
    return datetime.strftime(value, '%Y-%m-%dT%H:%M')

@app.template_filter('admin_format_date')
def admin_format_date(value):
    return datetime.strftime(value, '%Y-%m-%d')

@app.template_filter('format_label')
def format_label(value):
    return value.replace("_", " ")

def get_resource_class(resource_type):
    class_names = get_class_names('admin_view.py')
    class_names.remove('FlaskAdmin')
    for x in class_names:
        if globals()[x].name == resource_type:
            return globals()[x]
    return None

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

def get_resource_pk(resource_type):
    resource_class = get_resource_class(resource_type)
    resource_obj = resource_class()
    if hasattr(resource_obj, 'pk'):
        return resource_obj.pk
    return 'id'

def render_template(*args, **kwargs):
    class_names = get_class_names('admin_view.py')
    class_names.remove('FlaskAdmin')
    resource_types = [globals()[x].name for x in class_names]
    template_attributes = {
        'resource_types': resource_types
    }
    template_attributes['permissions'] = {}
    for resource_type in resource_types:
        resource_class = get_resource_class(resource_type)
        resource_obj = resource_class()
        resource_permissions = { # default permissions
            "create": False,
            "read": True,
            "update": False,
            "delete": False,
            "export": False,
            "import": False,
        }
        if hasattr(resource_obj, 'permissions'):
            resource_permissions = resource_obj.permissions
        template_attributes['permissions'][resource_type] = resource_permissions

    if 'resource_type' in kwargs:
        original_pk = get_resource_pk(kwargs['resource_type'])

        if 'pagination' in kwargs:
            for index, item in enumerate(kwargs['pagination'].items):
                setattr(kwargs['pagination'].items[index], 'pk', getattr(item, original_pk))

        if 'resource' in kwargs:
            setattr(kwargs['resource'], 'pk', getattr(kwargs['resource'], original_pk))

    return real_render_template(*args, **kwargs, **template_attributes)

def get_editable_attributes(resource_type):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model

    primary_key_columns = model.__table__.primary_key.columns.keys()
    ignore_columns = ['created_at', 'updated_at'] + primary_key_columns
    if hasattr(resource_class, 'protected_attributes'):
        ignore_columns = resource_class.protected_attributes + ignore_columns


    model_attributes = []
    for column in model.__table__.columns:
        model_attributes.append({
            'name': str(column.name),
            'type': str(column.type)
        })

    editable_attributes = []
    for attribute in model_attributes:
        if attribute['name'] not in ignore_columns:
            editable_attributes.append(attribute)

    return editable_attributes

def validate_resource_attribute(resource_type, attribute, initial_value):
    attribute_value = None
    if attribute['type'] == 'VARCHAR' or attribute['type'] == 'TEXT' or attribute['type'] == 'JSON':
        attribute_value = initial_value if initial_value else None
    elif attribute['type'] == 'INTEGER':
        attribute_value = initial_value if initial_value else None
    elif attribute['type'] == 'BOOLEAN':
        if not isinstance(initial_value, bool):
            attribute_value = initial_value.lower() == 'true'
        attribute_value = bool(initial_value)

    return attribute_value
class LoginForm(FlaskForm):
    phone = StringField('Phone', validators=[DataRequired()])
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
        # username/phone & password to be picked from app config
        # to understand the primary field names and avoid conflicts
        phone = form.phone.data
        password = form.password.data

        user = User.query.filter_by(mobile_number=phone).first()

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
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    per_page = 5
    page = request.args.get("page", default=1, type=int)
    primary_key_column = model.__table__.primary_key.columns.keys()[0]
    pagination = model.query.order_by(primary_key_column).paginate(page=page, per_page=per_page, error_out=False)
    list_display = resource_class.list_display
    return render_template('resource/list.html', pagination=pagination, resource_type=resource_type, list_display=list_display)

@admin.route('/resource/<string:resource_type>/create', methods=['GET', 'POST'])
@login_required
def resource_create(resource_type):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    editable_attributes = get_editable_attributes(resource_type)

    if request.method == 'GET':
        return render_template('resource/create.html', resource_type=resource_type, editable_attributes=editable_attributes)

    attributes_to_save = {}
    for attribute in editable_attributes:
        attribute_value = request.form.get(attribute['name'])
        validated_attribute_value = validate_resource_attribute(resource_type, attribute, attribute_value)
        attributes_to_save[attribute['name']] = validated_attribute_value

    new_resource = model(**attributes_to_save)
    db.session.add(new_resource)
    db.session.commit()

    return redirect(url_for('.resource_list', resource_type=resource_type))

@admin.route('/resource/<string:resource_type>/<string:resource_id>/edit', methods=['GET', 'POST'])
@login_required
def resource_edit(resource_type, resource_id):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    resource = model.query.get(resource_id)

    if not resource:
        return redirect(url_for('.resource_list'))

    editable_attributes = get_editable_attributes(resource_type)

    if request.method == 'GET':
        return render_template('resource/edit.html', resource_type=resource_type, resource=resource, editable_attributes=editable_attributes)

    for attribute in editable_attributes:
        attribute_value = request.form.get(attribute['name'])
        validated_attribute_value = validate_resource_attribute(resource_type, attribute, attribute_value)
        setattr(resource, attribute['name'], validated_attribute_value)

    db.session.commit()

    return redirect(url_for('.resource_list', resource_type=resource_type))

@admin.route('/resource/<string:resource_type>/<string:resource_id>/delete', methods=['POST'])
@login_required
def resource_delete(resource_type, resource_id):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    resource = model.query.get(resource_id)

    if resource:
        db.session.delete(resource)
        db.session.commit()

    return redirect(url_for('.resource_list', resource_type=resource_type))

@admin.route("/resource/<string:resource_type>/download", methods=['GET'])
@login_required
def resource_download(resource_type):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    resources = model.query.all()
    output = io.StringIO()
    writer = csv.writer(output)

    downloadable_attributes = model.__table__.columns.keys()

    writer.writerow(downloadable_attributes) # csv header
    for resource in resources:
        line = []
        for attribute in downloadable_attributes:
            line.append(getattr(resource, attribute))
        writer.writerow(line)
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=" + admin_label_plural(resource_type) + ".csv"})

@admin.route("/resource/<string:resource_type>/download-sample", methods=['GET'])
@login_required
def resource_download_sample(resource_type):
    output = io.StringIO()
    writer = csv.writer(output)

    uploadable_attributes = get_editable_attributes(resource_type)
    col_names = [attribute['name'] for attribute in uploadable_attributes]
    writer.writerow(col_names) # csv header
    writer.writerow([]) # print a blank second row

    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=" + admin_label_plural(resource_type) + "-sample.csv"})

@admin.route("/resource/<string:resource_type>/upload", methods=['GET', 'POST'])
@login_required
def resource_upload(resource_type):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model

    uploadable_attributes = get_editable_attributes(resource_type)

    if request.method == 'POST':
        uploaded_file = request.files['file']
        col_names = [attribute['name'] for attribute in uploadable_attributes]
        csvData = pd.read_csv(uploaded_file, usecols=col_names)
        for i,row in csvData.iterrows():
            attributes_to_save = {}
            for attribute in uploadable_attributes:
                attribute_value = row[attribute['name']]
                if pd.isna(attribute_value):
                    attribute_value = None
                if attribute['type'] == 'VARCHAR' or attribute['type'] == 'TEXT' or attribute['type'] == 'JSON':
                    attribute_value = attribute_value if attribute_value else None
                elif attribute['type'] == 'INTEGER':
                    attribute_value = attribute_value if attribute_value else None
                elif attribute['type'] == 'BOOLEAN':
                    if not isinstance(attribute_value, bool):
                        attribute_value = attribute_value.lower() == 'true'
                    attribute_value = bool(attribute_value)
                attributes_to_save[attribute['name']] = attribute_value
            new_resource = model(**attributes_to_save)
            db.session.add(new_resource)
            db.session.commit()

        if uploaded_file:
            uploaded_file.filename = secure_filename(uploaded_file.filename)
            upload_file_to_s3(uploaded_file)

        flash('All ' + resource_type.capitalize() + ' uploaded!')
        return redirect(url_for('.resource_list', resource_type=resource_type))
    return render_template('resource/upload.html', resource_type=resource_type)
