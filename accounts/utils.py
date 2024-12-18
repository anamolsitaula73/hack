# accounts/utils.py

import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_via_email(email, otp):
    subject = 'Your OTP for Email Verification'
    message = f'Your OTP for email verification is {otp}.'
    from_email = settings.EMAIL_HOST_USER
    send_mail(subject, message, from_email, [email])
