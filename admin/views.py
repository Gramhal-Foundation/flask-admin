"""
Admin Blueprint Views

This module contains route handlers and views for the
Flask Blueprint named 'admin'.
The blueprint handles administrative routes and related functionality.

Dependencies:
    - Flask: Flask framework for web development.
    - Flask-Login: Extension for handling user authentication and sessions.
    - Flask-WTF: Extension for handling forms and form validation.
    - Other imported modules and classes (details in the import statements).

Routes and Functionality:
    - /: Redirects to the dashboard route.
    - /dashboard: Displays the admin dashboard.
    - /login: Handles user login and authentication.
    - /logout: Logs out the current user.
    - /resource/<string:resource_type>: Lists resources of a given type.
    - /resource/<string:resource_type>/create: Creates a new resource of
    the specified type.
    - /resource/<string:resource_type>/<string:resource_id>/edit: Edits an
    existing resource.
    - /resource/<string:resource_type>/<string:resource_id>/delete: Deletes an
    existing resource.
    - /resource/<string:resource_type>/download: Downloads resources as CSV.
    - /resource/<string:resource_type>/download-sample: Downloads a sample CSV
    for resource upload.
    - /resource/<string:resource_type>/upload: Handles resource
    upload from CSV.

Views:
    - 'index': Redirects to the dashboard.
    - 'dashboard': Displays the admin dashboard.
    - 'login': Handles user login.
    - 'logout': Logs out the user.
    - 'resource_list': Lists resources of a given type.
    - 'resource_create': Creates a new resource.
    - 'resource_edit': Edits an existing resource.
    - 'resource_delete': Deletes an existing resource.
    - 'resource_download': Downloads resources as CSV.
    - 'resource_download_sample': Downloads a sample CSV for resource upload.
    - 'resource_upload': Handles resource upload from CSV.

Custom Template Filters:
    - 'admin_label_plural': Returns the plural form of a label.
    - 'admin_format_datetime': Formats a datetime object.
    - 'format_label': Formats a label by replacing underscores with spaces.
"""

import ast
import csv
import io
import string
from datetime import date, datetime, timedelta

import boto3
import inflect
import pandas as pd
from admin_view import *
from admin_view import admin_configs
from flask import current_app as app
from models.crop import CropModel
from models.mandi import MandiModel
from models.user import UserModel
from sqlalchemy.orm import joinedload
from sqlalchemy import cast, Text, or_, desc, and_, func, asc   

# [TODO]: dependency on main repo
from db import db
from flask import Response, flash, redirect, jsonify
from flask import render_template as real_render_template
from flask import request, url_for
from flask_login import login_required, login_user, logout_user
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired
from models.salesReceipt import SaleReceiptModel
from . import admin
from flask_bcrypt import Bcrypt
from models.membership import UserMembership, MembershipPlans, UserWallet

# TODO: remove project dependency
from resources.whatsappBot.mandi_v2 import update_cs_mandi_data, update_cs_data_mandi_crop

bcrypt = Bcrypt()


def get_user_model_config():
    return admin_configs["user"]


def upload_file_to_s3(file, bucket_name="", acl="public-read"):
    """
    Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
    """
    if not app.config["S3_KEY"]:
        return None

    if not bucket_name:
        bucket_name = app.config["S3_BUCKET"]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=app.config["S3_KEY"],
        aws_secret_access_key=app.config["S3_SECRET"],
    )
    try:
        s3_client.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={"ACL": acl, "ContentType": file.content_type},
        )
        return "{}{}".format(app.config["S3_LOCATION"], file.filename)
    except Exception as e:
        print("Something Happened: ", e)
        return e


@admin.app_template_filter("admin_label_plural")
def admin_label_plural(label):
    """
    Custom template filter to convert a label into its plural form.

    Args:
        label (str): The label to be converted to its plural form.

    Returns:
        str: The plural form of the input label.
    """

    p = inflect.engine()
    formatted_label = label.replace("-", " ")
    formatted_label = p.plural_noun(formatted_label)
    formatted_label = string.capwords(formatted_label)
    return formatted_label


@admin.app_template_filter("admin_label_singular")
def admin_label_singular(label):
    formatted_label = label.replace("-", " ")
    formatted_label = string.capwords(formatted_label)
    return formatted_label


@admin.app_template_filter("admin_format_datetime")
def admin_format_datetime(value, format="%Y-%m-%d"):
    return datetime.strftime(value, format)


@admin.app_template_filter("format_label")
def format_label(value):
    """
    Custom template filter to format a label string.

    Args:
        value (str): The label string to be formatted.

    Returns:
        str: The formatted label string with underscores replaced by spaces.
    """

    return value.replace("_", " ")


def get_resource_class(resource_type):
    class_names = get_class_names("admin_view.py")
    class_names.remove("FlaskAdmin")
    for x in class_names:
        if globals()[x].name == resource_type:
            return globals()[x]
    return None


def get_class_names(file_path):
    """
    Retrieve a list of class names from a Python file.

    This function parses the given Python file using the
    abstract syntax tree (AST) to extract the names of all
    class definitions present in the file.

    Args:
        file_path (str): The path to the Python file to be parsed.

    Returns:
        list: A list of class names present in the file.
    """

    with open(file_path, "r", encoding="utf-8") as file:
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
    if hasattr(resource_obj, "pk"):
        return resource_obj.pk
    return "id"


def render_template(*args, **kwargs):
    """
    Custom template rendering function with extended attributes.

    This function is an extension of Flask's `render_template` function.
    It provides additional attributes to the template context,
    including a list of resource types and their associated permissions.

    Args:
        *args: Variable positional arguments for the
        template rendering function.
        **kwargs: Variable keyword arguments for
        the template rendering function.

    Returns:
        str: The rendered template with extended context attributes.
    """

    class_names = get_class_names("admin_view.py")
    class_names.remove("FlaskAdmin")
    resource_types = [globals()[x].name for x in class_names]
    template_attributes = {"resource_types": resource_types}
    template_attributes["permissions"] = {}
    for resource_type in resource_types:
        resource_class = get_resource_class(resource_type)
        resource_obj = resource_class()
        resource_permissions = {  # default permissions
            "create": False,
            "read": True,
            "update": False,
            "delete": False,
            "export": False,
            "import": False,
        }
        if hasattr(resource_obj, "permissions"):
            resource_permissions = resource_obj.permissions
        template_attributes["permissions"][resource_type] = resource_permissions

    if "resource_type" in kwargs:
        original_pk = get_resource_pk(kwargs["resource_type"])

        if "pagination" in kwargs:
            for index, item in enumerate(kwargs["pagination"].items):
                setattr(
                    kwargs["pagination"].items[index],
                    "pk",
                    getattr(item, original_pk),
                )

        if "resource" in kwargs:
            setattr(
                kwargs["resource"],
                "pk",
                getattr(kwargs["resource"], original_pk),
            )

    return real_render_template(*args, **kwargs, **template_attributes)


def get_editable_attributes(resource_type):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model

    primary_key_columns = model.__table__.primary_key.columns.keys()
    ignore_columns = ["created_at", "updated_at"] + primary_key_columns
    if hasattr(resource_class, "protected_attributes"):
        ignore_columns = resource_class.protected_attributes + ignore_columns

    model_attributes = []
    for column in model.__table__.columns:
        model_attributes.append(
            {"name": str(column.name), "type": str(column.type)})

    editable_attributes = []
    for attribute in model_attributes:
        if attribute["name"] not in ignore_columns:
            editable_attributes.append(attribute)

    return editable_attributes


def validate_resource_attribute(resource_type, attribute, initial_value):
    attribute_value = None
    if (
        "VARCHAR" in attribute["type"]
        or attribute["type"] == "TEXT"
        or attribute["type"] == "JSON"
    ):
        attribute_value = initial_value if initial_value else None
    elif attribute["type"] == "INTEGER" or attribute["type"] == "FLOAT":
        attribute_value = initial_value if initial_value else None
    elif attribute["type"] == "BOOLEAN":
        if not isinstance(initial_value, bool):
            attribute_value = initial_value.lower() == "true"
        attribute_value = bool(initial_value)

    return attribute_value


class LoginForm(FlaskForm):
    """
    Form class for user login.

    This class defines a FlaskForm for handling user login.
    It includes fields for email and password,
    both of which are required for successful form submission.

    Attributes:
        email (StringField): The field for entering the user's email.
        password (PasswordField): The field for entering the user's password.
        submit (SubmitField): The field for submitting the login form.
    """

    phone = StringField("Phone", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@admin.route("/")
@login_required
def index():
    """
    Redirects to the dashboard route.

    This route handler function redirects the user to the 'dashboard' route.
    The user must be logged in to access this route.

    Returns:
        werkzeug.wrappers.response.Response: A redirection response
        to the dashboard route.
    """
    default_route = url_for('.dashboard')
    if 'default-route-resource' in admin_configs:
        default_route = url_for('.resource_list', resource_type=admin_configs['default-route-resource'])
    return redirect(default_route)


@admin.route("/dashboard")
@login_required
def dashboard():
    """
    Displays the admin dashboard.

    This route handler function renders the 'dashboard.html' template,
    which displays the admin dashboard. The user must be
    logged in to access this route.

    Returns:
        str: The rendered dashboard template.
    """
    return render_template("dashboard.html")


@admin.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles user login and authentication.

    This route handler function handles both GET and POST requests
    for user login. If a POST request is received with valid form data,
    the user's email and password are validated against the database.
    If the credentials are valid, the user is logged in and redirected to
    the dashboard. If the credentials are invalid, an error message
    is flashed to the user.

    Returns:
        str: The rendered 'login.html' template with the login form.
            If a POST request with invalid credentials is received,
            the template will display the error message in
            the flashed message area.
        werkzeug.wrappers.response.Response: A redirection response
        to the dashboard route if the user's credentials are valid.
    """
    form = LoginForm()
    if form.validate_on_submit():
        # username/phone & password to be picked from app config
        # to understand the primary field names and avoid conflicts
        phone = form.phone.data
        password = form.password.data
        user_model_config = get_user_model_config()
        user_model = user_model_config["model"]
        identifier = user_model_config["identifier"]
        user = user_model.query.filter(
            getattr(user_model, identifier) == phone).first()
        bcrypt.init_app(app)
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            default_route = url_for('.dashboard')
            if 'default-route-resource' in admin_configs:
                default_route = url_for('.resource_list', resource_type=admin_configs['default-route-resource'])
            return redirect(default_route)
        else:
            flash("Invalid credentials. Please try again.", "error")

    return render_template("login.html", form=form)


@admin.route("/logout")
@login_required
def logout():
    """
    Logs out the current user.

    This route handler function logs out the currently
    logged-in user and redirects them to the 'login' route.

    Returns:
        werkzeug.wrappers.response.Response: A redirection
        response to the login route.
    """
    logout_user()
    return redirect(url_for(".login"))


def filter_resources(model, list_display, search_query, page, per_page):
    primary_key_column = model.__table__.primary_key.columns.keys()[0]
    if search_query:
        or_conditions = []
        for column_name in list_display:
            column = model.__table__.columns.get(column_name)
            if column is not None:
                or_conditions.append(cast(column, Text).ilike(f'%{search_query}%'))

        if or_conditions:
            search_condition = or_(*or_conditions)
            pagination = model.query.filter(search_condition).order_by(primary_key_column).paginate(page=page, per_page=per_page, error_out=False)
        else:
            pagination = model.query.order_by(primary_key_column).paginate(page=page, per_page=per_page, error_out=False)
    else:
        pagination = model.query.order_by(primary_key_column).paginate(
            page=page, per_page=per_page, error_out=False
        )
    return pagination


@admin.route("/resource/<string:resource_type>", methods=["GET", "POST"])
@login_required
def resource_list(resource_type):
    """
    Lists resources of a specific type.

    This route handler function displays a paginated list of resources
    of the given resource type. The resources are retrieved from the
    corresponding model class. The list is paginated, and the number
    of items per page is determined by the 'per_page' variable.

    Args:
        resource_type (str): The type of resource to list.

    Returns:
        str: The rendered 'resource/list.html' template with the paginated list
        of resources, including the pagination controls and relevant
        information about the resource type and list display attributes.
    """
    # TODO: hardcoding to be removed
    if resource_type == 'mandi-receipt':
        return redirect(url_for('.resource_filter', resource_type=resource_type, status='pending'))

    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    is_custom_template = resource_class.is_custom_template
    per_page = 20
    page = request.args.get("page", default=1, type=int)
    search_query = request.args.get("search", default="")
    primary_key_column = model.__table__.primary_key.columns.keys()[0]
    list_display = resource_class.list_display
    pagination = filter_resources(model, list_display, search_query, page, per_page)
    if is_custom_template:
        pagination = model.query.filter(model.is_approved is None).order_by(primary_key_column).paginate(
            page=page, per_page=1, error_out=False
        )
        processed_data = get_preprocess_data(pagination, list_display)
        return render_template(
            "resource/custom-list.html",
            pagination=pagination,
            resource_type=resource_type,
            list_display=list_display,
            processed_data=processed_data,
            search_query=search_query
        )
    else:
        return render_template(
            "resource/list.html",
            pagination=pagination,
            resource_type=resource_type,
            list_display=list_display,
            search_query=search_query,
        )


@admin.route(
    "/resource/<string:resource_type>/create",
    methods=["GET", "POST"],
)
@login_required
def resource_create(resource_type):
    """
    Create a new resource of the specified type.

    This route handler function handles both GET and POST requests
    for creating a new resource of the given type.
    On a GET request, it renders the 'resource/create.html'
    template, which displays a form for entering information
    to create a new resource.
    On a POST request, the function processes the form data,
    validates and converts the attributes, creates a new resource object,
    and adds it to the database.

    Args:
        resource_type (str): The type of resource to create.

    Returns:
        werkzeug.wrappers.response.Response: A redirection response to
        the resource list page after successful creation. On a GET request,
        returns the rendered template with the create form.
        On a POST request, redirects to the resource list page.
    """
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    editable_attributes = get_editable_attributes(resource_type)

    if request.method == "GET":
        return render_template(
            "resource/create.html",
            resource_type=resource_type,
            editable_attributes=editable_attributes,
        )

    attributes_to_save = {}

    for attribute in editable_attributes:
        attribute_value = request.form.get(attribute["name"])
        if attribute["name"] == admin_configs["user"]["secret"]:
            attribute_value = get_hashed_password(attribute_value)

        validated_attribute_value = validate_resource_attribute(
            resource_type, attribute, attribute_value
        )
        attributes_to_save[attribute["name"]] = validated_attribute_value

    new_resource = model(**attributes_to_save)
    db.session.add(new_resource)
    db.session.commit()

    return redirect(url_for(".resource_list", resource_type=resource_type))


@admin.route(
    "/resource/<string:resource_type>/<string:resource_id>/edit",
    methods=["GET", "POST"],
)
@login_required
def resource_edit(resource_type, resource_id):
    """
    Edit an existing resource of the specified type.

    This route handler function handles both GET and POST requests for
    editing an existing resource of the given type. On a GET request,
    it renders the 'resource/edit.html' template, which displays a form
    pre-filled with the current attributes of the resource.
    On a POST request, the function processes the form data,
    validates and converts the attributes, updates the resource object,
    and commits the changes to the database.

    Args:
        resource_type (str): The type of resource to edit.
        resource_id (str): The ID of the resource to edit.

    Returns:
        werkzeug.wrappers.response.Response: A redirection response
        to the resource list page after successful editing.
        On a GET request, returns the rendered template with the edit
        form pre-filled.
        On a POST request, redirects to the resource list page.
        If the resource does not exist, redirects to the resource list page.
    """
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    resource = model.query.get(resource_id)

    if not resource:
        return redirect(request.referrer or url_for(".resource_list", resource_type=resource_type))

    editable_attributes = get_editable_attributes(resource_type)

    if request.method == "GET":
        return render_template(
            "resource/edit.html",
            resource_type=resource_type,
            resource=resource,
            editable_attributes=editable_attributes,
            admin_configs=admin_configs,
        )

    if hasattr(resource_class, "revisions") and hasattr(resource_class, "revision_model") and resource_class.revisions:
        revision_model = resource_class.revision_model
        revision_pk = resource_class.revision_pk
        existing_record = SaleReceiptModel.query.filter(
            SaleReceiptModel.booklet_number==resource.booklet_number,
            SaleReceiptModel.receipt_id==resource.receipt_id,
            SaleReceiptModel.mandi_id==resource.mandi_id,
            SaleReceiptModel.crop_id==resource.crop_id,
            SaleReceiptModel.is_approved==True,
            func.date(SaleReceiptModel.receipt_date)==func.date(resource.receipt_date)
        ).first()

        if existing_record and existing_record.id != resource.id:
            return jsonify({"error": "another record already exists with same booklet, receipt and mandi. Please go back and update with correct values."})

        cloned_attributes_to_save = {}
        for column, value in resource.__dict__.items():
            if column in ['_sa_instance_state', 'created_at', 'updated_at', 'promised_token', 'token_amount']:
                continue

            if column == 'id':
                cloned_attributes_to_save[revision_pk] = value
                continue

            cloned_attributes_to_save[column] = value

        cloned_resource = revision_model(**cloned_attributes_to_save)
        db.session.add(cloned_resource)
        db.session.commit()

    for attribute in editable_attributes:
        if attribute["name"] in request.form:
            attribute_value = request.form.get(attribute["name"])
            if attribute["name"] == admin_configs["user"]["secret"]:
                if attribute_value == "" or attribute_value is None:
                    continue
                attribute_value = get_hashed_password(attribute_value)

            validated_attribute_value = validate_resource_attribute(
                resource_type, attribute, attribute_value
            )
            setattr(resource, attribute["name"], validated_attribute_value)

    if resource_type == 'mandi-receipt':
        updated_mandi = MandiModel.query.get(resource.mandi_id)
        updated_crop = CropModel.query.get(resource.crop_id)
        setattr(resource, 'mandi_name', updated_mandi.mandi_name)
        setattr(resource, 'mandi_name_hi', updated_mandi.mandi_name_hi)
        setattr(resource, 'crop_name', updated_crop.crop_name)
        setattr(resource, 'crop_name_hi', updated_crop.crop_name_hi)

    db.session.commit()

    # call after update hook
    if hasattr(resource_class, 'after_update_callback'):
        resource_class.after_update_callback()

    if resource_type == 'mandi-receipt' and resource.is_approved:
        update_cs_mandi_data(sale_receipt=resource, forced=True)
        update_cs_data_mandi_crop(sale_receipt=resource, forced=True)

    return redirect(request.referrer or url_for(".resource_list", resource_type=resource_type))


@admin.route(
    "/resource/<string:resource_type>/<string:resource_id>/delete",
    methods=["POST"],
)
@login_required
def resource_delete(resource_type, resource_id):
    """
    Delete an existing resource of the specified type.

    This route handler function handles POST requests for deleting an
    existing resource of the given type. It retrieves the resource by
    its ID, deletes it from the database, and commits the changes.
    After deletion, the function redirects to the resource list page.

    Args:
        resource_type (str): The type of resource to delete.
        resource_id (str): The ID of the resource to delete.

    Returns:
        werkzeug.wrappers.response.Response: A redirection response to
        the resource list page after successful deletion.
    """
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    resource = model.query.get(resource_id)

    cloned_resource = resource
    if resource:
        db.session.delete(resource)
        db.session.commit()

    if cloned_resource and resource_type == 'mandi-receipt':
        update_cs_mandi_data(sale_receipt=cloned_resource, forced=True)
        update_cs_data_mandi_crop(sale_receipt=cloned_resource, forced=True)

    return redirect(request.referrer or url_for(".resource_list", resource_type=resource_type))


@admin.route("/resource/<string:resource_type>/download", methods=["GET"])
@login_required
def resource_download(resource_type):
    """
    Download a CSV file containing the data of resources of the specified type.

    This route handler function handles GET requests for downloading a CSV file
    containing the data of resources of the given type. It retrieves all
    resources of the specified type from the database, creates a CSV
    file containing the data, and returns the CSV file as a
    downloadable attachment.

    Args:
        resource_type (str): The type of resource to download.

    Returns:
        werkzeug.wrappers.response.Response: A response containing the CSV
        file as an attachment with the appropriate headers for downloading.
    """

    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    output = io.StringIO()
    writer = csv.writer(output)

    downloadable_attributes = model.__table__.columns.keys()
    search_query = request.args.get("search", default="")
    list_display = resource_class.list_display
    pagination = filter_resources(model, list_display, search_query, 1, None)
    resources = pagination.items

    writer.writerow(downloadable_attributes)  # csv header
    for resource in resources:
        line = []
        for attribute in downloadable_attributes:
            line.append(getattr(resource, attribute))
        writer.writerow(line)
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename="
            + admin_label_plural(resource_type)
            + ".csv"
        },
    )


@admin.route(
    "/resource/<string:resource_type>/download-sample",
    methods=["GET"],
)
@login_required
def resource_download_sample(resource_type):
    """
    Download a CSV file template for uploading new resources of the
    specified type.

    This route handler function handles GET requests for downloading
    a CSV file template for uploading new resources of the given type.
    It generates a CSV file header row with the attributes that can
    be uploaded for the specified resource type and returns the
    CSV file template as a downloadable attachment.

    Args:
        resource_type (str): The type of resource for which to download
        the CSV template.

    Returns:
        werkzeug.wrappers.response.Response: A response containing the CSV
        file template as an attachment with the appropriate headers for
        downloading.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    uploadable_attributes = get_editable_attributes(resource_type)
    col_names = [attribute["name"] for attribute in uploadable_attributes]
    writer.writerow(col_names)  # csv header
    writer.writerow([])  # print a blank second row

    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename="
            + admin_label_plural(resource_type)
            + "-sample.csv"
        },
    )


@admin.route(
    "/resource/<string:resource_type>/upload",
    methods=["GET", "POST"],
)
@login_required
def resource_upload(resource_type):
    """
    Uploads a CSV file containing data for the specified resource type.

    Args:
        resource_type (str): The type of resource being uploaded.

    Returns:
        If a POST request is made with a CSV file, the function processes
        the uploaded data and adds new resource instances to the database.
        Redirects to the resource list page after processing.
        If a GET request is made, renders the upload form.
    """
    resource_class = get_resource_class(resource_type)
    model = resource_class.model

    uploadable_attributes = get_editable_attributes(resource_type)

    if request.method == "POST":
        uploaded_file = request.files["file"]
        col_names = [attribute["name"] for attribute in uploadable_attributes]
        csv_data = pd.read_csv(uploaded_file, usecols=col_names)
        for row in csv_data.iterrows():
            attributes_to_save = {}
            for attribute in uploadable_attributes:
                attribute_value = row[attribute["name"]]
                if pd.isna(attribute_value):
                    attribute_value = None
                if (attribute["type"]) in ["VARCHAR", "TEXT", "JSON"]:
                    attribute_value = attribute_value or None
                elif attribute["type"] == "INTEGER":
                    attribute_value = attribute_value or None
                elif attribute["type"] == "BOOLEAN":
                    if not isinstance(attribute_value, bool):
                        attribute_value = attribute_value.lower() == "true"
                    attribute_value = bool(attribute_value)
                attributes_to_save[attribute["name"]] = attribute_value
            new_resource = model(**attributes_to_save)
            db.session.add(new_resource)
            db.session.commit()

        if uploaded_file:
            uploaded_file.filename = secure_filename(uploaded_file.filename)
            upload_file_to_s3(uploaded_file)

        flash("All " + resource_type.capitalize() + " uploaded!")
        return redirect(url_for(".resource_list", resource_type=resource_type))
    return render_template("resource/upload.html", resource_type=resource_type)


def get_hashed_password(password):
    """
    Hashes a password using Bcrypt.

    Parameters:
    - password (str): The password to be hashed.

    Returns:
    str: The hashed password encoded as a UTF-8 string.

    Raises:
    None

    Example:
    hashed_password = get_hashed_password('my_secure_password')
    """
    if password == "" or password is None:
        return password

    bcrypt.init_app(app)
    return bcrypt.generate_password_hash(password, 10).decode("utf-8")


def get_preprocess_data(pagination, list_display):
    processed_data = []

    for resource in pagination.items:
        image_data = []
        button_data = []
        other_data = []
        receipt_date = getattr(resource, "receipt_date")
        formatted_receipt_date = receipt_date.strftime("%Y-%m-%d")
        formatted_time = receipt_date.strftime("%I:%M %p")

        for item in list_display:
            if item == "receipt_image_url":
                image_data.append(getattr(resource, item))
            elif item == "is_approved":
                button_data.extend(
                    [("Edit", resource.id), ("Approve", resource.id), ("Reject", resource.id)])
            elif item != "receipt_date":
                other_data.append((item, getattr(resource, item)))

        other_data.append(("receipt_date", formatted_receipt_date))
        other_data.append(("Time", formatted_time))

        processed_data.append((image_data, button_data, other_data))

    return processed_data


@admin.route('/update_approval_status', methods=['POST'])
def update_approval_status():
    try:
        data = request.json
        action = data.get('action')
        receipt_id = data.get('receipt_id')


        print('fff')
        sale_receipt = SaleReceiptModel.query.get(receipt_id)
        
        print('fff')
        existing_record = SaleReceiptModel.query.filter(
            SaleReceiptModel.booklet_number==sale_receipt.booklet_number,
            SaleReceiptModel.receipt_id==sale_receipt.receipt_id,
            SaleReceiptModel.mandi_id==sale_receipt.mandi_id,
            SaleReceiptModel.crop_id==sale_receipt.crop_id,
            SaleReceiptModel.is_approved==True,
            func.date(SaleReceiptModel.receipt_date)==func.date(sale_receipt.receipt_date)
        ).first()

        print('fff')
        if existing_record and existing_record.id != sale_receipt.id:
            return jsonify({"error": "another record already exists with same booklet, receipt and mandi. Please go back and update with correct values."})

        print('fff')

        if action == 'approve':
            sale_receipt.is_approved = True
            sale_receipt.token_amount = sale_receipt.promised_token
        elif action == 'reject':
            sale_receipt.is_approved = False
            sale_receipt.token_amount = 0

        db.session.commit()

        if sale_receipt.is_approved == True:
            # Add earning wallet plan to user membership start
            membership_plan_id = ""

            if sale_receipt.token_amount == 10:
                membership_plan_id = "earned_days_01"
            elif sale_receipt.token_amount == 8:
                membership_plan_id = "earned_days_02"
            elif sale_receipt.token_amount == 6:
                membership_plan_id = "earned_days_03"
            elif sale_receipt.token_amount == 2:
                membership_plan_id = "earned_days_04"

            UserMembership(
                user_id=sale_receipt.user_id,
                membership_plan_id=membership_plan_id,
                payment_src_id="earned_days",
                notes="earned via sale receipt"
            ).commit()

        if action == 'approve':
            update_cs_mandi_data(sale_receipt=sale_receipt)
            update_cs_data_mandi_crop(sale_receipt=sale_receipt)

        return jsonify({'success': True, 'message': 'Approval status updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@admin.route("/resource/<string:resource_type>/<string:status>")
@login_required
def resource_filter(resource_type, status):
    resource_class = get_resource_class(resource_type)
    model = resource_class.model
    is_custom_template = resource_class.is_custom_template
    # per_page = 5
    page = request.args.get("page", default=1, type=int)
    mandi = request.args.get("mandi")
    crop = request.args.get('crop')
    if(mandi):
        mandi_id = int(mandi)
    if(crop):
        crop_id = int(crop)
    # primary_key_column = model.__table__.primary_key.columns.keys()[0]
    # TODO: filter not working
    # pagination = model.query.order_by(primary_key_column).paginate(
    #     page=page, per_page=per_page, error_out=False
    # )

    # cs_user_details
    cs_users = UserModel.query.filter(UserModel.roles=='cs_users').order_by(asc(UserModel.name)).all()
    print('csuser', cs_users)
    list_display = resource_class.list_display
    if is_custom_template:
        filter_conditions = []

        selected_mandi = None
        selected_crop = None
        if mandi:
            filter_conditions.append(model.mandi_id == mandi_id)
            selected_mandi = mandi_id
        if crop:
            filter_conditions.append(model.crop_id == crop_id)
            selected_crop = crop_id

        if not filter_conditions:
            pending_filter = (model.is_approved == None,)
            all_filter = (model.is_approved != None,)
        else:
            pending_filter = and_(*(model.is_approved == None, *filter_conditions))
            all_filter = and_(*(model.is_approved != None, *filter_conditions))

        pending_pagination = model.query.filter(*pending_filter).order_by(SaleReceiptModel.id).paginate(page=page, per_page=1, error_out=False)
        print('total', pending_pagination.total)
        all_pagination = model.query.options(joinedload(SaleReceiptModel.versions)).filter(*all_filter).order_by(desc(SaleReceiptModel.receipt_date)).paginate(page=page, per_page=10, error_out=False)

        if status == 'pending':
            pagination = pending_pagination
        else:
            pagination = all_pagination

        mandis = MandiModel.query.order_by(MandiModel.mandi_name).all()
        crops = CropModel.query.order_by(CropModel.crop_name).all()

        return render_template(
            "resource/custom-list.html",
            pagination=pagination,
            pending_pagination=pending_pagination,
            all_pagination=all_pagination,
            resource_type=resource_type,
            list_display=list_display,
            mandis=mandis,
            crops=crops,
            selected_mandi=selected_mandi,
            selected_crop=selected_crop,
            cs_users=cs_users
        )
