# Generated by Django 2.2.28 on 2024-06-05 17:17

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='accounts',
            old_name='password',
            new_name='password1',
        ),
    ]
