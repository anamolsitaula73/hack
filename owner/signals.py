from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import VenueOwner

@receiver(post_save, sender=VenueOwner)
def send_verification_email(sender, instance, **kwargs):
    if instance.verified and instance.user.email:  # Check if the user is verified and has an email
        try:
            send_mail(
                'Registration Verified',
                'Congratulations, your registration has been verified. You can now log in and manage your venues.',
                settings.DEFAULT_FROM_EMAIL,  # Use the default from email address from settings
                [instance.user.email],
                fail_silently=False,
            )
        except Exception as e:
            # Handle any email sending errors here
            print(f'Error sending email: {e}')
