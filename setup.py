from setuptools import find_packages, setup

extras_require = {"aws": ["boto"]}

install_requires = [
    "Flask>=0.7",
    "alembic",
    "inflect",
    "boto3",
    "pandas",
    "Flask-Login",
    "Flask-WTF",
    "Werkzeug",
    "WTForms",
    "SQLAlchemy",
]

setup(
    name="flask-admin",
    version="0.1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
)
