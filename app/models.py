
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db.models import TextField
from datetime import timedelta, datetime
from django.contrib.auth.models import Group, Permission

from django.contrib.auth.models import AbstractUser

from .token_generator import generate_unique_token_for_user
from django.contrib.auth.models import AbstractUser
from django.utils import timezone






# Create your models here.

class Meep(models.Model):
    user = models.ForeignKey(User, related_name='meeps', on_delete=models.DO_NOTHING)
    body = models.CharField('body',max_length=1050)
    
    likes = models.ManyToManyField(User, related_name='meep_like', blank=True)
    image = models.ImageField(upload_to='meep_images', blank=True, null=True)
    video = models.FileField(upload_to='meep_videos', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
   
    
    # Keep track or count of likes

    def number_of_likes(self):
        return self.likes.count()
    
    def num_comments(self):
        return self.comments.count()

    def __str__(self):
        return(
            f"{self.user} "
            f"({self.created_at:%Y-%m-%d %H:%M}): "
            f"{self.body}..."
        )

class UTF8MB4TextField(TextField):
    def db_type(self, connection):
        if 'mysql' in connection.settings_dict['ENGINE']:
            return 'longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        return super().db_type(connection)
    



class Comment(models.Model):
    
    body = UTF8MB4TextField('body', max_length=250)
    meep = models.ForeignKey(Meep, related_name='comments', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
       return f"Comment by {self.user.username} on {self.meep}: {self.body}"
    


class Report(models.Model):
    report_type = models.CharField(max_length=100)
    meep = models.ForeignKey(Meep, related_name='reports', on_delete=models.CASCADE)
    description = models.TextField()
    is_anonymous = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)




class Profile(models.Model):
          
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    follows = models.ManyToManyField("self", related_name='followed_by', symmetrical=False, blank=True)
    date_modified = models.DateTimeField(auto_now=True)
    profile_image = models.ImageField(null=True, blank=True, upload_to="images/")
    profile_bio = models.CharField('profile_bio',null=True, blank=True, max_length=500)

    
    homepage_link = models.CharField(null=True, blank=True, max_length=100)
    facebook_link = models.CharField(null=True, blank=True, max_length=100)
    instagram_link = models.CharField(null=True, blank=True, max_length=100)
    linkedin_link = models.CharField(null=True, blank=True, max_length=100)

    def __str__(self):
        return self.user.username
    
    def save(self, *args, **kwargs):
    # Check if the user is following another user
     if self.pk is not None:
        orig = Profile.objects.get(pk=self.pk)
        if not set(orig.follows.all()).issuperset(set(self.follows.all())):
            new_follows = self.follows.exclude(pk__in=orig.follows.all())
            # Iterate over the newly followed users and create a notification for each one
            for followed_user in new_follows:
                Notification.objects.create(
                    receiver=followed_user,
                    sender=self.user,
                    type='follow',
                    content=f"{self.user.username} started following you.",
                    profile=self,
                )

     super(Profile, self).save(*args, **kwargs)

# Connect the post_save signal of the User model to the create_profile function
@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


def generate_notification_content(notification):
    action = notification.type
    user = notification.sender
    
    if action == 'follow':
        return f"{user.username} started following you."
    elif action == 'like':
        return f"{user.username} liked your meep."
    elif action == 'comment':
        return f"{user.username} commented on your meep."
    elif action == 'share':
        return f"{user.username} shared your meep."
    else:
        return ''
    
class Notification(models.Model):
    content = models.TextField('content', max_length=500, blank=True, null=True)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_notifications')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_notifications')
    type = models.CharField(max_length=50, choices=[
        ('like', 'Like'),
        ('comment', 'Comment'),
        ('share', "Share"),
        ('mention', 'Mention'),
        ('report', 'Report'),  # Added 'report' type for reporting notifications
    ])
    meep = models.ForeignKey(Meep, on_delete=models.CASCADE, null=True)
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    mentioned = models.BooleanField(default=False)
    is_new = models.BooleanField(default=True)
    read = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.type} by {self.sender.username} on {self.meep}: {self.content}"
    
    @classmethod
    def create_report_notification(cls, sender, receiver, meep, content):
        report = Report.objects.create(meep=meep, description=content)
        return cls.objects.create(
        sender=sender,
        receiver=receiver,
        type='report',
        meep=meep,
        content=content
    )



class EmailVerificationToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    expires_at = models.DateTimeField()

    @classmethod
    def create(cls, user):   
        # Check if a token already exists for the user
        existing_token = cls.objects.filter(user=user).first()
        if existing_token:
            # Update the existing token's expiration time
            existing_token.expires_at = timezone.now() + timedelta(days=1)
            existing_token.save()
            return existing_token

        # Generate a token
        token = generate_unique_token_for_user(user)
        print("Generated token:", token)
        
        # Set expiration time (e.g., 24 hours from now)
        expiration_time = timezone.now() + timedelta(days=1)
        print("Expiration time:", expiration_time)
        
        # Create and return the token object
        token_obj = cls.objects.create(user=user, token=token, expires_at=expiration_time)
        print("Token object created:", token_obj)
        
        return token_obj


class CustomUser(AbstractUser):
    # Add related_name arguments to prevent clashes with auth.User model
    email_verified = models.BooleanField(default=False)
    groups = models.ManyToManyField(Group, verbose_name=('groups'), blank=True, related_name='custom_user_set')
    user_permissions = models.ManyToManyField(Permission, verbose_name=('user permissions'), blank=True, related_name='custom_user_set')

