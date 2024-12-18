from django.db import models
from tinymce.models import HTMLField
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

class Accounts(models.Model):
    id = models.AutoField(primary_key=True)
    email=models.CharField(max_length=50)
    
    username=models.CharField(max_length=50)
    password1 = models.CharField(max_length=128, null=True, blank=True)
  

class UserOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)



 