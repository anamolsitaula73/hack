# route_manager/forms.py
from django import forms
from django import forms
from .models import Route
from django.contrib.auth.forms import AuthenticationForm

class RouteManagerLoginForm(AuthenticationForm):
    username = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))





from django import forms
from .models import Route

class RouteForm(forms.ModelForm):
    class Meta:
        model = Route
        fields = ['route_name', 'starting_point', 'destination', 'route_data']

from django import forms
from .models import BusStop, Route

class BusStopForm(forms.ModelForm):
    class Meta:
        model = BusStop
        fields = ['route', 'name', 'latitude', 'longitude']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['route'].queryset = Route.objects.all()
