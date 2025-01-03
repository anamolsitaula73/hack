# Generated by Django 5.1.4 on 2024-12-15 16:15

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        (
            "owner",
            "0022_rename_business_registration_number_venueowner_bus_registration_number_and_more",
        ),
    ]

    operations = [
        migrations.RenameField(
            model_name="venue",
            old_name="name",
            new_name="driver_name",
        ),
        migrations.RenameField(
            model_name="venue",
            old_name="total_slots",
            new_name="seats",
        ),
        migrations.RenameField(
            model_name="venue",
            old_name="available_slots",
            new_name="seats_available",
        ),
        migrations.RemoveField(
            model_name="venue",
            name="average_cost_per_person",
        ),
    ]
