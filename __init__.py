"""
Admin Blueprint Module

This module defines a Flask Blueprint named 'admin' for handling
administrative routes and related functionality. The blueprint includes
specific views for managing administrative tasks
and can be registered with a Flask app to integrate these routes.

Example usage:
    from flask import Flask
    from admin import admin

    app = Flask(__name__)
    app.register_blueprint(admin)

Module Structure:
    - 'admin': The main Blueprint object for administrative routes.
    - 'views': Module containing views and route handlers associated
    with the 'admin' blueprint.
"""
from flask import Blueprint

admin = Blueprint(
    "admin", __name__, template_folder="templates", static_folder="static"
)
