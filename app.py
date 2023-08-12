# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd
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
@login_required
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

if __name__ == '__main__':
    app.run(debug=True)
