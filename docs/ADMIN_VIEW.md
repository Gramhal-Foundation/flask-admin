## Setting up admin_view.py
The `admin_view.py` is the configuration file for everything that appears in the admin view. You must configure this file properly in order to access the admin dashboard.

Table of contents:
  - [Admin Configs](#admin-configs)
  - [ModelAdmin class](#modeladmin-class)
  - [Basic setup](#basic-setup)
  - [Permissions](#permissions)
  - [Primary key](#primary-key)
  - [Protected attributes](#protected-attributes)


### Admin Configs
The `admin_configs` variable determines the user configurations for login & registration that the admin functionality needs to use.

The `admin_configs` has the following attributes:
1. `model`: This represents the user model in your application that stores the user details. If there is no User model yet, you must create it before updating this file.
2. `identifier`: The column in the user table that will be used to uniquely identify and validate the user during authentication.
3. `secret`: The column in the user table that will be used to verify entered credentials.

Once configured properly, it should look like this:
```py
admin_configs = {
    'user': {
        'model': User,
        'identifier': 'mobile',
        'secret': 'password'
    }
}
```

### ModelAdmin class
Each model you want to show in your admin portal must be defined in the `admin_view.py` file.

Let's understand in detail through an example. But first, let's write down what exactly we are going to do:
1. We want to list the users in the admin portal.
2. The functionality for create, read, update, delete should be there along with bulk upload and CSV download.
3. Admins can do all the operations for users.
4. Editors can read & export the users but cannot do other operations.
5. Other users roles should not access users list.

### Basic setup
Lets consider only having the list of users in the admin dashboard without any restrictions on roles. This is how your class setup would look like:
```py
class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
```

Few things to notice here:
1. The name of the class should be in the format `ModelAdmin`. The `Admin` suffix should be present.
2. `FlaskAdmin` class must be inherited.
3. Class properties:
   1. `model`: Represents which Flask model the admin dashboard should load.
   2. `name`: Used for display name and URL slug.
   3. `list_display`: The attributes that should be displayed in the list.

Once this is done, you can navigate to the `/admin` route and should see "Users" in the sidebar. Once you click, you should see all the options.

### Permissions
To set up permissions, you must set up the permissions class property for your ModelAdmin class. Simply put, it will look like this.
```py
class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
    permissions = {
        "create": True,
        "read": True,
        "update": True,
        "delete": True,
        "export": True,
        "import": True,
    }
```

However, this way to define permissions will not be used in most cases. The limitation with this approach is that it does not change for any user role.
To have dynamic permissions based on the current user that is accessing the admin dashboard, prefer a below format:
```py
from flask_login import current_user # the instance of user model who is logged in

def get_user_permissions():
  if current_user.role == 'admin':
    return {
        "create": True,
        "read": True,
        "update": True,
        "delete": True,
        "export": True,
        "import": True,
    }

  if current_user.role == 'editor':
    return {
        "create": False,
        "read": True, # editor view user list
        "update": False,
        "delete": False,
        "export": True, # editor can do export
        "import": False,
    }

  return {
      "create": False,
      "read": False,
      "update": False,
      "delete": False,
      "export": False,
      "import": False,
  }

class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')

    def __init__(self):
        super().__init__()
        self.permissions = get_user_permissions()
```

In this example, the function `get_user_permissions` returns the list of permissions based on the user role. You can extend the functionality for this function or create your own logic to calculate the user permissions based on your project structure.


### Primary key
By default, the `id` column is picked up as the primary key for every model. This is used to uniquely identify every entity for edit & delete actions.

In case your model has a different name of the primary key, you can configure the admin class like this:
```py
class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
    pk = '_id'
```

### Protected attributes
For some models, there may be some attributes that you may want to be protected and not be editable via admin dashboard. For example, there can be a `last_active_date` for a user that you want only to be controlled by your login view.

You can define these protected attributes as a class property as a list. These attributes will no longer appear in the admin dashboard.
```py
class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
    protected_attributes = ['last_active_date', 'token_expires_at']
```

### Related attributes as dropdown
There can be related models that you would prefer to select by their label or name instead of putting a finding the corresponding id or primary key value and putting it correctly in the text field. Dropdowns are handy. For example, you would prefer to select a language as a dropdown for a user instead of looking through languages table, finding the corresponding language id and putting it in the language id field when creating or editing a user. This is where, related attributes come in to save the day.

Defining editable related attributes are pretty straightforward. In you class, you can put in a list/array like this:
```py
class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
    editable_relations_dropdown = [
        {
            "key": "language_id", # the foreign key field you wish to replace with the dropdown
            "label": "language", # the label of the field
            "related_model": LanguageModel, # the related model
            "related_label": "name", # the related model field that will display as label of each dropdown option
            "related_key": "id", # the related model primary key field for each dropdown option value
        }
    ]
```

All the editable relations defined through this attribute will replace the corresponding foreign key field with a dropdown having options defined. This will impact both create resource page and edit resource page, where in edit resource, the existing option will come pre-selected.
