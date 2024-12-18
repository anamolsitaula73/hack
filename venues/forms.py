# venues/forms.py
from django import forms
from .models import Venue, PricingPackage

class VenueForm(forms.ModelForm):
    class Meta:
        model = Venue
        fields = ['name', 'address', 'description', 'contact_email']
        widgets = {
            'contact_email': forms.EmailInput(attrs={'readonly': 'readonly'}),
        }

class PricingPackageForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)  # Extract the user from kwargs
        super(VenueForm, self).__init__(*args, **kwargs)
        if user and user.is_authenticated:
            self.fields['contact_email'].initial = user.email  # Set initial value to user's email
            self.fields['contact_email'].widget.attrs['readonly'] = True  # Make field read-only 


    class Meta:
        model = PricingPackage
        fields = ['package_name', 'price', 'details','contact_email']
        widgets = {
            'contact_email': forms.EmailInput(attrs={'readonly': 'readonly'}),
        }
