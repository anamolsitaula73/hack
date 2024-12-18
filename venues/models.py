# venues/models.py
from django.db import models

class Venue(models.Model):
    id = models.AutoField(primary_key=True) 
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=255)
    description = models.TextField()
    contact_email = models.EmailField(unique=True)

    def __str__(self):
        return self.name

class PricingPackage(models.Model):
    id = models.AutoField(primary_key=True) 
    venue = models.ForeignKey(Venue, related_name='packages', on_delete=models.CASCADE)
    package_name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    details = models.TextField()
    contact_email = models.EmailField()
    


    def __str__(self):
        return f'{self.package_name} - {self.venue.name}'
