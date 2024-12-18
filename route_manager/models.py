from django.db import models

class Route(models.Model):
    route_name = models.CharField(max_length=255)
    starting_point = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    route_data = models.TextField()

    def __str__(self):
        return self.route_name



class BusStop(models.Model):
    name = models.CharField(max_length=255)
    latitude = models.FloatField()
    longitude = models.FloatField()
    route = models.ForeignKey(Route, on_delete=models.CASCADE, related_name='bus_stops')

# Bus Model
class Bus(models.Model):
    number_plate = models.CharField(max_length=15)
    driver_name = models.CharField(max_length=100)
    route = models.ForeignKey(Route, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Bus {self.number_plate} - Driver: {self.driver_name}"
