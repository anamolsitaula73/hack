# owner/models.py
from django.db import models
from django.contrib.auth.models import User
from tinymce.models import HTMLField
from route_manager.models import Route 

class VenueOwner(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bus_registration_number = models.CharField(max_length=100)
    bus_registration_photo = models.ImageField(upload_to='business_registrations/')
    verified = models.BooleanField(default=False)
    route = models.ForeignKey(Route, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username

class Venue(models.Model):
    id = models.AutoField(primary_key=True)
    driver_name = models.CharField(max_length=100)  # Changed name to driver_name
    address = models.CharField(max_length=255)
    description = models.TextField()
    contact_email = models.EmailField(unique=True)
    zip_code = models.CharField(max_length=10, default=44207)  # New field for zip code
    seats = models.PositiveIntegerField(default=0)  # Changed total_slots to seats
    occupancy = models.PositiveIntegerField(default=0)
    contact_num = models.PositiveIntegerField(default=0)
    
    image = models.ImageField(upload_to='venue_images/', null=True, blank=True)
    seats_available = models.PositiveIntegerField(editable=False)  # Changed available_slots to seats_available

    def save(self, *args, **kwargs):
        self.seats_available = self.seats - self.occupancy
        super().save(*args, **kwargs)  # Save the object with updated available seats


    def __str__(self):
        return self.driver_name 

    @staticmethod
    def recommend_venues(event_type, location, budget):
        venues = Venue.objects.filter(packages__price__lte=budget)
        if location:
            venues = venues.filter(address__icontains=location)
        return venues.distinct()

class PricingPackage(models.Model):
    id = models.AutoField(primary_key=True)
    venue = models.ForeignKey(Venue, related_name='packages', on_delete=models.CASCADE)
    package_name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    details = models.TextField()
    contact_email = models.EmailField()

    def __str__(self):
        return f'{self.package_name} - {self.venue.name}'


class Booking(models.Model):
    id = models.AutoField(primary_key=True)
    contact_email = models.EmailField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    venue = models.ForeignKey(Venue, on_delete=models.CASCADE)
    date = models.DateField()
    time = models.TimeField()
    number_of_guests = models.IntegerField()
    booked_at = models.DateTimeField(auto_now_add=True)
    confirmed = models.BooleanField(default=False) 
    checked_out = models.BooleanField(default=False)
    
    def __str__(self):
        return f'Booking {self.id} for {self.venue.name}'
    

    
from django.db import models
from django.contrib.auth.models import User

class BusLocation(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    latitude = models.FloatField()
    longitude = models.FloatField()
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.owner.username} - {self.latitude}, {self.longitude} at {self.timestamp}"
