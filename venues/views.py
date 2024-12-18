# venues/views.py
from django.shortcuts import render, redirect, get_object_or_404
from .models import Venue, PricingPackage
from .forms import VenueForm, PricingPackageForm

def register_venue(request):
    email_already_registered = False

    if request.user.is_authenticated:
        if request.method == 'POST':
            form = VenueForm(request.POST)
            if form.is_valid():
                venue = form.save(commit=False)
                venue.contact_email = request.user.email

                if Venue.objects.filter(contact_email=venue.contact_email).exists():
                    email_already_registered = True
                else:
                    venue.save()
                    return redirect('venue_list')
        else:
            form = VenueForm(initial={'contact_email': request.user.email})

        return render(request, 'venues/register_venue.html', {
            'form': form,
            'email_already_registered': email_already_registered,
        })
    else:
        return render(request, 'venues/register_venue.html', {'form': None})



def venue_list(request):
    if request.user.is_authenticated:
        venues = Venue.objects.filter(contact_email=request.user.email)
    else:
        venues = Venue.objects.none()  # Return an empty queryset if the user is not authenticated
    return render(request, 'venues/venue_list.html', {'venues': venues})

def add_pricing_package(request, venue_id):
    venue = get_object_or_404(Venue, pk=venue_id)
    if request.method == 'POST':
        form = PricingPackageForm(request.POST)
        if form.is_valid():
            pricing_package = form.save(commit=False)
            pricing_package.venue = venue  # Ensure venue is set
            pricing_package.save()
            return redirect('venue_list')
    else:
        form = PricingPackageForm(initial={'contact_email': request.user.email})
    return render(request, 'venues/add_pricing_package.html', {'form': form})



