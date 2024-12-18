# venues/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
# views.py
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Venue, Booking
from .forms import BookingForm
from .forms import VenueImageForm
from django.template.loader import render_to_string
from django.views.generic import TemplateView


from django.core.mail import send_mail, BadHeaderError
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import VenueOwnerSignUpForm, LoginForm, VenueForm, PricingPackageForm, BookingForm
from .models import VenueOwner, Venue, PricingPackage ,Booking

from django.conf import settings
from django.core.mail import send_mail, BadHeaderError
from django.contrib import messages
from django.shortcuts import render, redirect
from .forms import VenueOwnerSignUpForm
from .models import VenueOwner

from django.conf import settings
from django.core.mail import send_mail, BadHeaderError
from django.contrib import messages
from django.shortcuts import render, redirect
from django.db import IntegrityError
from .forms import VenueOwnerSignUpForm
from .models import VenueOwner

def venue_owner_signup(request):
    if request.method == 'POST':
        form = VenueOwnerSignUpForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save()  # Save the User instance
            bus_registration_number = form.cleaned_data.get('bus_registration_number')
            bus_registration_photo = form.cleaned_data.get('bus_registration_photo')
            route = form.cleaned_data.get('route')  # Extract the selected route
            
            # Check if the user is already a VenueOwner
         
                # Send email notification
            try:
                    send_mail(
                        'Pending Registration',
                        'Your registration is pending verification.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
            except BadHeaderError:
                    messages.error(request, 'Invalid header found.')
            except Exception as e:
                    messages.error(request, f'An error occurred: {e}')

            return redirect('login_owner')

            # Redirect to signup page or wherever appropriate

    else:
        form = VenueOwnerSignUpForm()

    return render(request, 'owner/signup_owner.html', {'form': form})



from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import LoginForm
from .models import BusLocation

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        latitude = request.POST.get('latitude')
        longitude = request.POST.get('longitude')

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.venueowner.verified:
                    # Store location in the database
                    BusLocation.objects.create(owner=user, latitude=latitude, longitude=longitude)

                    login(request, user)
                    return redirect('venue_detail')
                else:
                    messages.error(request, 'Your registration is still pending approval.')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'owner/login_owner.html', {'form': form})


@login_required
def home_view(request):
    if request.method == 'POST':
        form = VenueForm(request.POST, user=request.user)
        if form.is_valid():
            form.instance.user = request.user
            form.save()
            return redirect('venue_detail')
    else:
        form = VenueForm(user=request.user)
    return render(request, 'owner/home_owner.html', {'form': form})

def venue_detail(request):
    if request.user.is_authenticated:
        venues = Venue.objects.filter(contact_email=request.user.email)
    else:
        venues = Venue.objects.none()
    return render(request, 'owner/venue_detail.html', {'venues': venues})

def owner_add_pricing_package(request, venue_id):
    venue = get_object_or_404(Venue, id=venue_id)
    initial_email = request.user.email if request.user.is_authenticated else None
    
    if request.method == 'POST':
        form = PricingPackageForm(request.POST, initial_email=initial_email)
        if form.is_valid():
            pricing_package = form.save(commit=False)
            pricing_package.venue = venue
            pricing_package.save()
            return redirect('owner_pricing_packages', venue_id=venue.id)
    else:
        form = PricingPackageForm(initial={'contact_email': initial_email})

    return render(request, 'owner/owner_add_pricing_package.html', {'form': form, 'venue': venue})

@login_required
def owner_pricing_packages(request, venue_id):
    # Fetch the venue object
    venue = get_object_or_404(Venue, id=venue_id)
    
    # Fetch the pricing packages associated with the venue
    packages = PricingPackage.objects.filter(venue=venue)

    # Prepare the form instances for existing packages
    package_form_pairs = [(package, PricingPackageForm(instance=package)) for package in packages]

    if request.method == 'POST':
        package_id = request.POST.get('package_id')
        if 'delete' in request.POST:
            # Delete the selected pricing package
            package = get_object_or_404(PricingPackage, id=package_id)
            package.delete()
            # Redirect to the same view after deletion
            return redirect('owner_pricing_packages', venue_id=venue_id)
        elif 'save' in request.POST:
            # Save changes to the selected pricing package
            package = get_object_or_404(PricingPackage, id=package_id)
            form = PricingPackageForm(request.POST, instance=package)
            if form.is_valid():
                form.save()
                # Redirect to the same view after saving
                return redirect('owner_pricing_packages', venue_id=venue_id)
    
    # Render the template with the venue and package form pairs
    context = {
        'venue': venue,
        'package_form_pairs': package_form_pairs,
    }
    
    return render(request, 'owner/owner_pricing_packages.html', context)

def delete_package(request, venue_id, package_id):
    venue = get_object_or_404(Venue, id=venue_id)
    package = get_object_or_404(PricingPackage, id=package_id)

    if request.method == 'POST':
        package.delete()
        return redirect('owner_pricing_packages', venue_id=venue.id)
    
    return redirect('owner_pricing_packages', venue_id=venue.id)

def user_packages(request, venue_id):
    venue = get_object_or_404(Venue, id=venue_id)
    packages = PricingPackage.objects.filter(venue=venue)

    context = {
        'venue': venue,
        'packages': packages,
    }
    return render(request, 'owner/user_pricing_packages.html', context)

def edit_package(request, venue_id, package_id):
    venue = get_object_or_404(Venue, id=venue_id)
    package = get_object_or_404(PricingPackage, id=package_id, venue=venue)

    if request.method == "POST":
        form = PricingPackageForm(request.POST, instance=package)
        if form.is_valid():
            form.save()
            return redirect('owner_pricing_packages', venue_id=venue.id)
    else:
        form = PricingPackageForm(instance=package)

    context = {
        'venue': venue,
        'form': form,
        'package': package,
    }
    return render(request, 'owner/edit_package.html', context)

@login_required
def edit_venue(request, pk):
    venue = get_object_or_404(Venue, id=pk)

    if request.method == 'POST':
        form = VenueForm(request.POST, request.FILES, instance=venue)
        if form.is_valid():
            form.save()
            return redirect('venue_detail')  # Redirect to venue detail page after saving
        else:
            print("Form errors:", form.errors)
    else:
        form = VenueForm(instance=venue)
    
    context = {
        'form': form,
        'venue': venue,
    }
    return redirect('venue_detail')  # Redirect to venue detail page after saving



def booking_success(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    return render(request, 'accounts/booking_success.html', {'booking': booking})




from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import Venue, Booking
from .forms import BookingForm
from django.conf import settings


@login_required

def book_venue(request, venue_id):
    venue = get_object_or_404(Venue, id=venue_id)
    
    if request.method == 'POST':
        form = BookingForm(request.POST, user_email=request.user.email)
        if form.is_valid():
            booking = form.save(commit=False)
            booking.user = request.user
            booking.venue = venue
            booking.contact_email = request.user.email

            number_of_guests = booking.number_of_guests

            # Check if venue has available slots
            if venue.available_slots < number_of_guests:
                # If not enough slots available, show an error message
                form.add_error(None, 'Venue is packed. Not enough available slots.')
            else:
                # Save the booking
                booking.save()

               
                # Send email to user
                user_subject = 'Booking Requested'
                user_message = render_to_string('emails/booking_confirmation_user.html', {
                    'user': request.user,
                    'venue': venue,
                    'booking': booking,
                })
                user_plain_message = strip_tags(user_message)
                send_mail(user_subject, user_plain_message, None, [request.user.email], html_message=user_message)

                # Send email to venue owner
                owner_subject = 'New Booking Request for Your Venue'
                owner_message = render_to_string('emails/booking_notification_owner.html', {
                    'owner': venue.name,
                    'venue': venue,
                    'booking': booking,
                })
                owner_plain_message = strip_tags(owner_message)
                send_mail(owner_subject, owner_plain_message, None, [venue.contact_email], html_message=owner_message)

                return redirect('booking_success', booking_id=booking.id)
    else:
        form = BookingForm(user_email=request.user.email)

    return render(request, 'accounts/book_venue.html', {'venue': venue, 'form': form})


@login_required

def view_bookings(request, venue_id):
    venue = get_object_or_404(Venue, id=venue_id)

    bookings = Booking.objects.filter(venue=venue).order_by('-date')

    context = {
        'venue': venue,
        'bookings': bookings
    }
    return render(request, 'owner/view_bookings.html', context)




def cancel_owner_booking(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    user = booking.user
    venue = booking.venue

    if request.method == "POST":
        print(f"Booking ID: {booking.id}, Venue ID: {venue.id}, Venue Name: {venue.name}")
        
        # Update venue slots and occupancy before deleting the booking, if confirmed
        if booking.confirmed:
            venue.occupancy -= booking.number_of_guests
            venue.available_slots += booking.number_of_guests
            venue.save()

        booking.delete()

        # Send email to user
        subject_user = 'Booking Canceled'
        html_message_user = render_to_string('owner_emails/booking_canceled_user.html', {
            'user': user,
            'venue': venue,
        })
        user_email = user.email
        send_mail(subject_user, '', settings.DEFAULT_FROM_EMAIL, [user_email], html_message=html_message_user)

        # Send email to venue owner
        subject_owner = 'Booking Canceled'
        html_message_owner = render_to_string('owner_emails/booking_canceled_owner.html', {
            'venue': venue,
            'booking': booking,
        })
        owner_email = venue.contact_email
        send_mail(subject_owner, '', settings.DEFAULT_FROM_EMAIL, [owner_email], html_message=html_message_owner)

        return redirect('view_bookings', venue_id=venue.id)

    return render(request, 'owner/cancel_booking.html', {'booking': booking})


def edit_venue_image(request, venue_id):
    venue = get_object_or_404(Venue, pk=venue_id)
    if request.method == 'POST':
        form = VenueImageForm(request.POST, request.FILES, instance=venue)
        if form.is_valid():
            form.save()
            return redirect('venue_detail')  # Adjust this to redirect to the appropriate page
    else:
        form = VenueImageForm(instance=venue)
    return render(request, 'owner/edit_venue_image.html', {'form': form, 'venue': venue})




@login_required
def confirm_booking(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    venue = booking.venue  # Get the venue related to the booking

  # Redirect to an unauthorized page if the user is not the owner

    # Check if the number of guests exceeds available slots
    if booking.number_of_guests > venue.available_slots:
        # Handle the case where there are too many guests
        return render(request, 'errors/booking_error.html', {
            'message': 'The number of guests exceeds the available slots for this venue.'
        })

    # Confirm the booking and update the venue's occupancy and available slots
    booking.confirmed = True
    booking.save()

    # Update venue occupancy and available slots
    venue.occupancy += booking.number_of_guests
    venue.available_slots -= booking.number_of_guests
    venue.save()

    # Send email to user
    user_subject = 'Booking Confirmed'
    user_message = render_to_string('emails/booking_confirmed_user.html', {
        'user': booking.contact_email,
        'venue': venue,
        'booking': booking,
    })
    user_plain_message = strip_tags(user_message)
    send_mail(user_subject, user_plain_message, None, [booking.contact_email], html_message=user_message)

    # Send email to venue owner
    owner_subject = 'New Booking Confirmed'
    owner_message = render_to_string('emails/booking_confirmed_owner.html', {
        'owner': venue.name,  # Assuming venue.owner is a User object
        'venue': venue,
        'booking': booking,
    })
    owner_plain_message = strip_tags(owner_message)
    send_mail(owner_subject, owner_plain_message, None, [venue.contact_email], html_message=owner_message)

    return redirect('view_bookings', venue_id=venue.id)
 

 
def check_out_booking(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    venue = booking.venue
    
    if request.method == 'POST':
        if booking.confirmed and not booking.checked_out:
            # Increase available slots
            venue.occupancy -= booking.number_of_guests
            venue.save()

            # Mark the booking as checked out
            booking.checked_out = True
            booking.save()

            messages.success(request, 'Booking marked as checked out and slots updated successfully.')
        else:
            messages.error(request, 'Booking is not confirmed or already checked out.')
    
    return redirect('view_bookings', venue_id=venue.id)


class AboutUsView(TemplateView):
    template_name = 'owner/aboutus.html'


from django.shortcuts import render, redirect
from .models import VenueOwner

from django.shortcuts import render, redirect
import json
from .models import VenueOwner, Route
from route_manager.models import  BusStop

from django.shortcuts import render, redirect
import json
from .models import VenueOwner, Route
from route_manager.models import BusStop
# def show_routes(request):
#     if request.user.is_authenticated:
#         try:
#             venue_owner = VenueOwner.objects.get(user=request.user)
#             route = venue_owner.route
#             route_data = route.route_data

#             if isinstance(route_data, str):
#                 route_data = json.loads(route_data)

#             # Fetch bus stops related to the route
#             # bus_stops = BusStop.objects.filter(route=route)

#             # Convert bus stop data to a format that can be used in JavaScript
#             route_bus_stops = BusStop.objects.filter(route=route)
#             bus_stops_data = [
#             {'name': bus_stop.name, 'latitude': bus_stop.latitude, 'longitude': bus_stop.longitude}
#             for bus_stop in route_bus_stops
#         ]
            
           

#             # return render(request, 'route_manager/view_saved_routes.html', {'routes': route_data, 'all_bus_stops': bus_stops})


#             return render(request, 'owner/show_routes.html', {
#                 'route': route,
#                 'route_data': route_data,
#                 'all_bus_stops': bus_stop}
#             )
#         except VenueOwner.DoesNotExist:
#             return redirect('profile')
#         except Exception as e:
#             return render(request, 'owner/show_routes.html', {'message': f"An error occurred: {str(e)}"})
#     else:
#         return redirect('login')


def show_routes(request):
    if not request.user.is_authenticated:
        return redirect('owner')

    
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
    return render(request, 'owner/show_routes.html', {'routes': route_data, 'all_bus_stops': bus_stops})


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from route_manager.models import Route, BusStop
from .models import VenueOwner

@login_required
def show_owner_route(request):
    try:
        # Fetch the VenueOwner associated with the logged-in user
        venue_owner = VenueOwner.objects.get(user=request.user)
    except VenueOwner.DoesNotExist:
        return redirect('home')  # Redirect if not a VenueOwner

    # Get the owner's associated route
    owner_route = venue_owner.route

    # Fetch all bus stops associated with the owner's route
    bus_stops = BusStop.objects.filter(route=owner_route)

    # Pass data to the template
    return render(request, 'owner/show_route.html', {
        'owner_route': owner_route,
        'bus_stops': bus_stops
    })

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import BusLocation

class GetLatestLocationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        location = BusLocation.objects.filter(owner=request.user).last()
        if location:
            return Response({
                "latitude": location.latitude,
                "longitude": location.longitude,
                "timestamp": location.timestamp,
            })
        return Response({"error": "No location data found"}, status=404)\
        



