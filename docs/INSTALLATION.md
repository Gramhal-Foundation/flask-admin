## Installation

### Pre-requisites
1. PostgreSQL
2. Python 3.8 or higher


### Installation Steps
1. You can simply install the package via pip. Run the following command:
   ```sh
   pip install git+https://github.com/Gramhal-Foundation/flask_admin.git
   ```
2. Add the following code to your main repo `app.py`. It should look like this:
   ```py
   # register login manager
   from flask_login import LoginManager
   app.secret_key = 'your-random-secret'
   login_manager = LoginManager(app)
   login_manager.login_view = 'admin.login'
   @login_manager.user_loader
   def load_user(user_id):
      return UserModel.query.get(user_id)

   # register admin blueprint
   from admin import admin
   app.register_blueprint(admin, url_prefix='/admin')

   if __name__ == '__main__':
      # your existing code
   ```
3. Create a new file `admin_view.py`. To reference what needs to be inside this file, you can look at the [sample admin_view.py](../examples/admin_view.py). Complete documentation of the structure of `admin_view.py` is mentioned [here](./ADMIN_VIEW.md).
4. Run your app. If your app runs on port 8000, you can access the admin login page via `http://localhost:8000/admin`.
