# events/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .forms import EventForm
from .models import Event
from owner.models import Venue
import requests
from datetime import datetime
@login_required
def create_event(request):
    if request.method == 'POST':
        form = EventForm(request.POST)
        if form.is_valid():
            event = form.save(commit=False)
            event.created_by = request.user
            event.save()
            return redirect('event_list')
    else:
        form = EventForm()
    return render(request, 'events/create_event.html', {'form': form})

@login_required
def event_list(request):
    events = Event.objects.filter(created_by=request.user)
    return render(request, 'events/event_list.html', {'events': events})

def get_weather_forecast(location, event_date):
    api_key = '2b2ab793ccbc4df3bd5140510242007'  # Replace with your WeatherAPI key
    url = f'http://api.weatherapi.com/v1/forecast.json?key={api_key}&q={location}&days=10'
    response = requests.get(url)

    # Check if the response status code is 200 (OK)
    if response.status_code != 200:
        print(f"Failed to get data from API. Status code: {response.status_code}")
        return None

    data = response.json()

    # Check if 'forecast' key exists in the response
    if 'forecast' not in data or 'forecastday' not in data['forecast']:
        print("Key 'forecast' or 'forecastday' not found in the response. Full response:")
        print(data)  # Log the entire response for debugging purposes
        return None

    # Find forecast closest to the event date
    forecast_date = datetime.strptime(event_date, '%Y-%m-%d').date()
    for forecast in data['forecast']['forecastday']:
        forecast_time = datetime.strptime(forecast['date'], '%Y-%m-%d').date()
        if forecast_time == forecast_date:
            return {
                'date': forecast_time,
                'temperature': forecast['day']['avgtemp_f'],  # Use 'avgtemp_c' for Celsius
                'description': forecast['day']['condition']['text'],
                'icon': forecast['day']['condition']['icon']
            }

    # Return None if no matching forecast is found
    print("No matching forecast found for the given date")
    return None

@login_required
def recommend_venues(request, event_id):
    event = get_object_or_404(Event, pk=event_id)
    
    if request.method == 'POST':
        form = EventForm(request.POST, instance=event)
        if form.is_valid():
            event = form.save(commit=False)
            event_type = form.cleaned_data['event_type']
            location = form.cleaned_data['location']
            budget = form.cleaned_data['event_budget']
            
            recommended_venues = Venue.recommend_venues(event_type, location, budget)
            
            # Get weather forecast
            weather_forecast = get_weather_forecast(location, str(event.event_date))
            
            return render(request, 'events/recommend_venues.html', {
                'event': event,
                'venues': recommended_venues,
                'form': form,
                'weather_forecast': weather_forecast
            })
    else:
        form = EventForm(instance=event)
        weather_forecast = get_weather_forecast(event.location, str(event.event_date))
    
    return render(request, 'events/recommend_venues.html', {
        'event': event,
        'form': form,
        'weather_forecast': weather_forecast
    })


def delete_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    event.delete()
    return redirect('event_list')