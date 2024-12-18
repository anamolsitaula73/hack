# events/models.py
from django.db import models
from django.contrib.auth.models import User

class Event(models.Model):
    EVENT_TYPES = [
        ('conference', 'Conference'),
        ('wedding', 'Wedding'),
        ('party', 'Party'),
        ('meeting', 'Meeting'),
    ]

    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    event_date = models.DateField()
    number_of_people = models.PositiveIntegerField()
    event_budget = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.event_type} on {self.event_date} at {self.location}'
