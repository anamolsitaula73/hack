from django.contrib import admin

# Register your models here.
from accounts.models import Accounts
from django.contrib import admin
from .models import Accounts,UserOTP

# venues/admin.py
from django.contrib import admin



class Accountsadmin(admin.ModelAdmin):
    list_display=('id','username',
                  'email','password1')


admin.site.register(Accounts,Accountsadmin)
