# Generated by Django 4.1.3 on 2023-06-23 17:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_useraccount_username'),
    ]

    operations = [
        migrations.RenameField(
            model_name='useraccount',
            old_name='phone_numbber',
            new_name='phone_number',
        ),
    ]
