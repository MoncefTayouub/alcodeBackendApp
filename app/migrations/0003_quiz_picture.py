# Generated by Django 5.1.3 on 2024-11-22 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_remove_question_audio_content_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='quiz',
            name='picture',
            field=models.FileField(blank=True, null=True, upload_to='img/'),
        ),
    ]
