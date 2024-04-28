# Generated by Django 5.0.4 on 2024-04-11 14:18

import app.models
import django.contrib.auth.models
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Meep',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('body', models.CharField(max_length=1050, verbose_name='body')),
                ('image', models.ImageField(blank=True, null=True, upload_to='meep_images')),
                ('video', models.FileField(blank=True, null=True, upload_to='meep_videos')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('likes', models.ManyToManyField(blank=True, related_name='meep_like', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, related_name='meeps', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('body', app.models.UTF8MB4TextField(max_length=250, verbose_name='body')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('meep', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='app.meep')),
            ],
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_modifies', models.DateTimeField(auto_now=True, verbose_name=django.contrib.auth.models.User)),
                ('profile_image', models.ImageField(blank=True, null=True, upload_to='images/')),
                ('profile_bio', models.CharField(blank=True, max_length=500, null=True, verbose_name='profile_bio')),
                ('homepage_link', models.CharField(blank=True, max_length=100, null=True)),
                ('facebook_link', models.CharField(blank=True, max_length=100, null=True)),
                ('instagram_link', models.CharField(blank=True, max_length=100, null=True)),
                ('linkedin_link', models.CharField(blank=True, max_length=100, null=True)),
                ('follows', models.ManyToManyField(blank=True, related_name='followed_by', to='app.profile')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField(blank=True, max_length=500, null=True, verbose_name='content')),
                ('type', models.CharField(choices=[('like', 'Like'), ('comment', 'Comment'), ('share', 'Share'), ('mention', 'Mention'), ('report', 'Report')], max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('mentioned', models.BooleanField(default=False)),
                ('is_new', models.BooleanField(default=True)),
                ('read', models.BooleanField(default=False)),
                ('meep', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.meep')),
                ('receiver', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_notifications', to=settings.AUTH_USER_MODEL)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_notifications', to=settings.AUTH_USER_MODEL)),
                ('profile', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.profile')),
            ],
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_type', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('is_anonymous', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('meep', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='app.meep')),
            ],
        ),
    ]
