from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

# Unregister the existing User model from admin
admin.site.unregister(User)

# Register it again (if you are customizing it)
admin.site.register(User, UserAdmin)
# Register your models here.
