# Generated by Django 5.0.6 on 2024-06-24 20:47

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("owner", "0010_alter_venue_available_slots_booking"),
    ]

    operations = [
        migrations.AlterField(
            model_name="booking",
            name="id",
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]
