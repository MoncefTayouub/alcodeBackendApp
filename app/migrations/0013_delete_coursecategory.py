# Generated by Django 5.1.3 on 2024-12-18 22:23

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0012_alter_serie_category'),
    ]

    operations = [
        migrations.DeleteModel(
            name='courseCategory',
        ),
    ]
