# events/forms.py
from django import forms
from .models import Event

class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        fields = ['event_type', 'event_date', 'number_of_people', 'event_budget', 'location']
        widgets = {
            'event_date': forms.DateInput(attrs={'type': 'date'}),
        }
