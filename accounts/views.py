# accounts/views.py
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import SignUpForm, LoginForm, OTPForm
from django.shortcuts import render, get_object_or_404, redirect
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from owner.models import Venue,Booking
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.generic import TemplateView

from datetime import date, datetime

from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters




from .utils import generate_otp, send_otp_via_email
from .models import UserOTP  # We'll create this model to store OTPs
from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from .forms import UserUpdateForm

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')

            user = form.save(commit=False)
            user.is_active = False  # Deactivate account till it is verified
            user.save()
            
            otp = generate_otp()
            send_otp_via_email(user.email, otp)
            
            UserOTP.objects.create(user=user, otp=otp)  # Save OTP in database
            request.session['email'] = user.email
            request.session['username'] = username  # Store username in session

            return redirect(reverse('verify_otp'))
    else:
        form = SignUpForm()
    return render(request, 'accounts/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                request.session['username'] = username  # Store username in session
                return redirect('/')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})

def logout_view(request):
    logout(request)
    try:
        del request.session['username']  # Remove username from session
    except KeyError:
        pass
    return redirect('login')

# @login_required
def home_view(request):
    username = request.session.get('username', None)
    venues = Venue.objects.all()
    return render(request, 'accounts/home.html', {'username': username, 'venues': venues})



def verify_otp_view(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            username = request.session.get('username')
            try:
                user = User.objects.get(username=username)
                user_otp = UserOTP.objects.get(user=user)
                
                if user_otp.otp == otp:
                    user.is_active = True
                    user.save()
                    login(request, user)
                    messages.success(request, 'Your account has been verified.')
                    return redirect('/')
                else:
                    messages.error(request, 'Invalid OTP')
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.')
            except UserOTP.DoesNotExist:
                messages.error(request, 'OTP does not exist.')
    else:
        form = OTPForm()
    
    return render(request, 'accounts/verify_otp.html', {'form': form})

def send_otp(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}. It is valid for 10 minutes.'
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)




User = get_user_model()    

def resend_otp_view(request):
    email = request.session.get('email')
    
    if email:
        # Generate a new OTP
        otp = generate_otp()
        cache.set(f'otp_{email}', otp, timeout=600)  # Store OTP in cache for 10 minutes

        # Update the OTP in the user's OTP record
        try:
            user = User.objects.get(email=email)
            user_otp, created = UserOTP.objects.get_or_create(user=user)
            user_otp.otp = otp
            user_otp.save()

            # Send the OTP via email
            send_otp_via_email(email, otp)
            messages.success(request, 'A new OTP has been sent to your email.')
        except User.DoesNotExist:
            messages.error(request, 'User does not exist.')
            return redirect('signup')
        except Exception as e:
            messages.error(request, f'Failed to send OTP: {e}')
            print(f'Error sending OTP: {e}')  # Debugging information
    else:
        messages.error(request, 'No email found in session. Please sign up again.')
        return redirect('signup')
    
    return redirect(reverse('verify_otp'))

      



    
def user_pricing_packages(request, venue_id):
    return render(request, 'owner/user_pricing_packages')




@login_required
def booked_venues(request):
    bookings = Booking.objects.filter(user=request.user).order_by('-id')

    today_date = date.today()
    now = datetime.now().time()

    def booking_is_expired(booking):
        if booking.date < today_date or (booking.date == today_date and booking.time < now):
            return True
        return False

    context = {
        'bookings': bookings,
        'booking_is_expired': booking_is_expired,
    }
    return render(request, 'accounts/booked_venues.html', context)



def cancel_booking(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    user = booking.user
    venue = booking.venue
    
    if request.method == "POST":
        venue.occupancy -= booking.number_of_guests
        venue.save()
        booking.delete()
        

        # Send email to user
        subject_user = 'Booking Canceled'
        html_message_user = render_to_string('emails/booking_canceled_user.html', {
            'user': user,
            'venue': venue,
        })
        user_email = user.email
        send_mail(subject_user, None, settings.DEFAULT_FROM_EMAIL, [user_email], html_message=html_message_user)

        # Send email to venue owner
        subject_owner = 'Booking Canceled'
        html_message_owner = render_to_string('emails/booking_canceled_owner.html', {
            'venue': venue,
            'booking': booking,
        })
        owner_email = venue.contact_email
        send_mail(subject_owner, None, settings.DEFAULT_FROM_EMAIL, [owner_email], html_message=html_message_owner)

        return redirect('booked_venues')

    return render(request, 'owner/booked_venues.html', {'bookings': Booking.objects.all()})




@login_required
def my_profile(request):
    if request.method == 'POST':
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)  # Update session to prevent logout
            messages.success(request, 'Your password was successfully updated.')
            return redirect('my-profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        password_form = PasswordChangeForm(request.user)
    
    context = {
        'password_form': password_form,
    }
    return render(request, 'accounts/my_profile.html', context)






@method_decorator(sensitive_post_parameters('old_password', 'new_password1', 'new_password2'), name='dispatch')
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'accounts/password_change.html'  # Replace with your template name
    success_url = reverse_lazy('password_change_done')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.method == 'POST':
            # Clear old password field if there are form errors
            if context.get('form').errors:
                context['form'].fields['old_password'].initial = ''
        return context
    



@login_required
def update_name(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        
        # Update user's first name and last name
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.save()

        messages.success(request, 'Your name has been updated successfully.')
        return redirect('my-profile')  # Replace with your profile page URL name
    
    return render(request, 'accounts/my_profile.html')    



class AboutUsView(TemplateView):
    template_name = 'accounts/aboutus.html'


from django.shortcuts import render
from route_manager.models import Route, BusStop
from owner.models import VenueOwner  # Import VenueOwner model
import json

def view_all_routes(request):
    # Fetch all saved routes, bus stops, and venue owners from the database
    routes = Route.objects.all()
    bus_stops = BusStop.objects.all()
    venue_owners = VenueOwner.objects.select_related('route', 'user').all()  # Efficiently fetch related data

    # Prepare the routes data to pass to the template
    route_data = []
    for route in routes:

        # Fetch the bus stops for each route
        route_bus_stops = bus_stops.filter(route=route)
        bus_stops_data = [
            {'name': bus_stop.name, 'latitude': bus_stop.latitude, 'longitude': bus_stop.longitude}
            for bus_stop in route_bus_stops
        ]

        # Fetch VenueOwner associated with the route (if any)
        route_venue_owners = venue_owners.filter(route=route)
        venue_owner_data = [
            {
                'username': venue_owner.user.username,
                'registration_number': venue_owner.bus_registration_number,
                'registration_photo': venue_owner.bus_registration_photo.url if venue_owner.bus_registration_photo else None,
                'verified': venue_owner.verified,
                'latitude': venue_owner.latitude,
                'longitude': venue_owner.longitude,
                'timestamp': venue_owner.timestamp
            }
            for venue_owner in route_venue_owners
        ]

        # Add the bus stop and venue owner data to the route data
        route_data.append({
            'route_name': route.route_name,
            'starting_point': route.starting_point,
            'destination': route.destination,
            'route_data': json.loads(route.route_data),  # Convert the route_data JSON back to a list of coordinates
            'bus_stops': bus_stops_data,  # Include bus stops data specific to this route
            'venue_owners': venue_owner_data  # Include all venue owners for this route
        })

    # Pass all bus stops, route data, and venue owners to the template
    all_owners = [
        {
            'username': owner.user.username,
            'route': owner.route.route_name if owner.route else "No Route Assigned",
            'registration_number': owner.bus_registration_number,
            'verified': owner.verified,
            'latitude':owner.latitude,
            'longitude':owner.longitude,
        }
        for owner in venue_owners
    ]
    for owner in all_owners:
     print(owner)


    return render(request, 'accounts/view_saved_routes.html', {
        'routes': route_data,
        'all_bus_stops': bus_stops,
        'owners':all_owners    # Pass the list of all owners
    })

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from owner.models import VenueOwner  # Assuming you have a VenueOwner model

class VenueOwnerByRouteView(APIView):
    def get(self, request, route_name):
        try:
            # Fetch venue owners by route name
            from owner.models import VenueOwner
            owners = VenueOwner.objects.filter(route="bhojad", verified=True)
            for owner in owners:
             print(owner.user.username, owner.route)


            # Prepare the data to return
            owners_data = []
            for owner in owners:
                owners_data.append({
                    'username': owner.user.username,  # Assuming 'user' is a ForeignKey to User model
                    'route': owner.route,
                    'bus_registration': owner.bus_registration_number,
                    'latitude': owner.latitude,
                    'longitude': owner.longitude,
                    'verified': owner.verified
                })

            return Response(owners_data, status=status.HTTP_200_OK)

        except Exception as e:
            # In case of any error, return a server error response
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

from rest_framework.response import Response
from rest_framework.decorators import api_view
from owner.models import VenueOwner

@api_view(['GET'])
def get_venue_owner_location(request):
    route = request.GET.get('route')
    
    if not route:
        return Response({'error': 'Route parameter is required'}, status=400)
    
    try:
        owner = VenueOwner.objects.filter(route__route_name=route).first()  # Assuming Route has route_name
        
        if not owner:
            return Response({'error': 'No venue owner found for this route'}, status=404)
        
        # Return the owner's location details as a response
        return Response({
            'ownerLocation': {
                'latitude': owner.latitude,
                'longitude': owner.longitude,
                'username': owner.user.username  # Assuming the User model has a username field
            }
        })

    except Exception as e:
        return Response({'error': str(e)}, status=500)
