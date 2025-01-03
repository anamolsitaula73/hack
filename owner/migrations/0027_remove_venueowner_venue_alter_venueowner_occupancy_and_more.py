# Generated by Django 5.1.4 on 2024-12-19 10:30

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("owner", "0026_venueowner_occupancy_venueowner_seats_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="venueowner",
            name="venue",
        ),
        migrations.AlterField(
            model_name="venueowner",
            name="occupancy",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="venueowner",
            name="seats",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="venueowner",
            name="seats_available",
            field=models.PositiveIntegerField(editable=False),
        ),
    ]
