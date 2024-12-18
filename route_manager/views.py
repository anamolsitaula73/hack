# route_manager/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from .forms import RouteManagerLoginForm
from .models import Route, Bus
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.http import JsonResponse
from .models import Route, BusStop
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import Route

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Route
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Route

from django.http import JsonResponse
from .models import Route
import json
from django.shortcuts import render, redirect
from .models import Route
from django.http import JsonResponse

from django.shortcuts import render, redirect
from .models import Route
from django.http import HttpResponse

# route_manager/views.py

from django.shortcuts import render

def empty_page(request):
    return render(request, 'empty_page.html')


from django.http import HttpResponse
from django.shortcuts import render

from django.http import HttpResponse
from django.shortcuts import render

# views.py
from django.http import HttpResponse
from django.shortcuts import render
from .models import Route  # Import your Route model

# views.py
from django.http import JsonResponse
from django.shortcuts import render
from .models import Route

from django.shortcuts import render, redirect
from .forms import RouteForm

from django.shortcuts import render, redirect
from .forms import RouteForm

from django.shortcuts import render, redirect
from .forms import RouteForm

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Route
from django.shortcuts import render, redirect
from .forms import RouteForm
from .models import Route
from django.http import JsonResponse
from django.shortcuts import render
from .models import Route
from .forms import RouteForm
from django.shortcuts import render

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Route

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import RouteForm

from django.shortcuts import render
from .models import Route

from django.shortcuts import render
from .models import Route
import json
from django.contrib.auth import logout

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.http import HttpResponseRedirect

def custom_login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        next_url = request.GET.get("next") or "/route_manager"  # Redirect to `next` if provided, else `/dashboard/`

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return HttpResponseRedirect(next_url)
        else:
            messages.error(request, "Invalid username or password")

    return render(request, "route_manager/login.html")


from django.shortcuts import render, redirect
from .models import Route, BusStop
import json

from django.shortcuts import render, redirect
from .models import Route, BusStop
import json

def view_saved_routes(request):
    if not request.user.is_authenticated:
        return redirect('route_manager_login')

    # Fetch all saved routes from the database
    routes = Route.objects.all()
    bus_stops = BusStop.objects.all()

    # Prepare the routes data to pass to the template
    route_data = []
    for route in routes:
        # Fetch the bus stops for each route
        route_bus_stops = BusStop.objects.filter(route=route)
        bus_stops_data = [
            {'name': bus_stop.name, 'latitude': bus_stop.latitude, 'longitude': bus_stop.longitude}
            for bus_stop in route_bus_stops
        ]

        # Add the bus stop data to the route data
        route_data.append({
            'route_name': route.route_name,
            'starting_point': route.starting_point,
            'destination': route.destination,
            'route_data': json.loads(route.route_data),  # Convert the route_data JSON back to a list of coordinates
            'bus_stops': bus_stops_data  # Include bus stops data specific to this route
        })

    # Pass all bus stops (for the table) and route data (for the map) to the template
    return render(request, 'route_manager/view_saved_routes.html', {'routes': route_data, 'all_bus_stops': bus_stops})

from django.shortcuts import redirect
from django.http import JsonResponse
from .forms import RouteForm

def save_route(request):
    if request.method == 'POST':
        form = RouteForm(request.POST)
        if form.is_valid():
            form.save()
           
            # Redirect to the view_saved_routes URL
            return redirect('view_saved_routes')
        else:
            # Handle invalid form data
            return render(request, 'route_manager/save_route.html', {
                'form': form,
                'errors': form.errors,
            })
    else:
        # Handle non-POST requests
        return render(request, 'route_manager/save_route.html', {
            'form': RouteForm()
        })




def route_list(request):
    # Fetch all routes and bus stops
    routes = Route.objects.all()
    bus_stops = BusStop.objects.all()

    return render(request, 'route_manager/routelist.html', {
        'routes': routes,
        'bus_stops': bus_stops,
    })


# Route Manager Login View
def route_manager_login(request):
    if request.method == "POST":
        form = RouteManagerLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('route_manager_home')
            else:
                form.add_error(None, "Invalid username or password.")
    else:
        form = RouteManagerLoginForm()

    return render(request, 'route_manager/login.html', {'form': form})

# Route Manager Home View
def route_manager_home(request):
    if not request.user.is_authenticated:
        return redirect('route_manager_login')

    routes = Route.objects.all()
    bus_stops = BusStop.objects.all()

    return render(request, 'route_manager/home2.html', {'routes': routes,'all_bus_stops': bus_stops})


def create_route(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            route = Route.objects.create(
                name=data['name'],
                starting_point=data['starting_point'],
                destination=data['destination'],  # This now comes from the form
            )

            # Save bus stops
            for stop in data['bus_stops']:
                BusStop.objects.create(
                    route=route,
                    lat=stop['lat'],
                    lon=stop['lon']
                )

            return JsonResponse({"success": True, "route_id": route.id}, status=201)
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)}, status=400)


# API View to Get Route Details
def get_route(request, route_id):
    try:
        route = Route.objects.get(id=route_id)
        route_data = {
            'start_lat': route.start_lat,
            'start_lon': route.start_lon,
            'end_lat': route.end_lat,
            'end_lon': route.end_lon,
            'name': route.name,
            'starting_point': route.starting_point,
            'destination': route.destination,
        }
        return JsonResponse({'route': route_data})
    except Route.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Route not found'}, status=404)

# Assign Route to Driver
def assign_route_to_driver(request, bus_id):
    if request.method == "POST":
        route_id = request.POST.get("route_id")
        try:
            bus = Bus.objects.get(id=bus_id)
            route = Route.objects.get(id=route_id)
            bus.route = route
            bus.save()
            return redirect('bus_details', bus_id=bus.id)
        except (Bus.DoesNotExist, Route.DoesNotExist):
            return JsonResponse({'success': False, 'message': 'Bus or Route not found'}, status=404)
    routes = Route.objects.all()
    return render(request, 'route_manager/assign_route.html', {'routes': routes})


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("login")

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import BusStop

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import BusStop


def create_bus_stop(request):
    if not request.user.is_authenticated:
        return redirect('route_manager_login')

    routes = Route.objects.all()
    return render(request, 'route_manager/create_bus_stop.html', {'routes': routes})


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
from .models import Route, BusStop

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import BusStopForm
from .models import BusStop

from django.shortcuts import render, redirect
from .forms import BusStopForm
from .models import BusStop

def save_bus_stop(request):
    if request.method == 'POST':
        form = BusStopForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('view_saved_routes')  # Make sure this URL name is defined in urls.py
        else:
            return render(request, 'route_manager/home2.html', {'form': form, 'errors': form.errors})
    else:
        form = BusStopForm()
    return render(request, 'route_manager/home2.html', {'form': form})
