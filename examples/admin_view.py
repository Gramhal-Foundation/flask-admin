from flask_login import current_user
from models import User, Post, Category, Organization

admin_configs = {
    'user': {
        'model': User,  # the user model, should be imported above
        'identifier': 'mobile',  # column name from user table
        'secret': 'password'  # column name from user table
    }
}


def get_user_roles():
    # current_user is an instance of the User model
    if not hasattr(current_user, 'roles'):
        return None
    return current_user.roles


def get_user_permissions(resource_model):
    user_roles = get_user_roles()

    if "admin" in user_roles:
        return {
            "create": True,
            "read": True,
            "update": True,
            "delete": True,
            "export": True,
            "import": True,
        }

    user_permissions = {
        "create": False,
        "read": False,
        "update": False,
        "delete": False,
        "export": False,
        "import": False,
    }

    if "editor" in user_roles and resource_model != User:
        user_permissions["read"] = True

    return user_permissions


class FlaskAdmin():
    def __init__(self):
        super().__init__()


class UserAdmin(FlaskAdmin):
    model = User
    name = 'user'
    list_display = ('name', 'phone_number')
    pk = '_id'

    def __init__(self):
        super().__init__()
        self.permissions = get_user_permissions(self.model)


class PostAdmin(FlaskAdmin):
    model = Post
    name = 'post'
    list_display = ('text', 'user_id', 'is_active')
    pk = '_id'

    def __init__(self):
        super().__init__()
        self.permissions = get_user_permissions(self.model)


class CategoryAdmin(FlaskAdmin):
    model = Category
    name = 'category'
    list_display = ('parent_category_id', 'title', 'is_active')
    pk = '_id'

    def __init__(self):
        super().__init__()
        self.permissions = get_user_permissions(self.model)
