# Generated by Django 5.1.4 on 2024-12-14 10:12

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("route_manager", "0010_remove_route_end_lat_remove_route_end_lng_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="route",
            name="destination",
            field=models.CharField(default="null", max_length=255),
        ),
        migrations.AlterField(
            model_name="route",
            name="route_name",
            field=models.CharField(default="null", max_length=255),
        ),
        migrations.AlterField(
            model_name="route",
            name="starting_point",
            field=models.CharField(default="null", max_length=255),
        ),
    ]