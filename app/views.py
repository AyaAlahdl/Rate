from datetime import timezone
import logging
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect,get_object_or_404
from django.contrib import messages
from .models import EmailVerificationToken, Profile, Meep, Comment, Notification
from .forms import MeepForm, SignUpForm, ProfilePicForm, CommentForm
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone



from django.core.mail import send_mail

from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required

from django.contrib.auth.models import User
from django.http import JsonResponse
from django.db import IntegrityError
from .utils import generate_unique_token_for_user


from .forms import AnonymousReportForm
from .models import Report
from django.contrib import messages
from django.http import HttpResponse
from django.conf import settings
from django.views.generic import View
import requests
import re



from django.shortcuts import render

from django.contrib.auth.views import PasswordResetView
from django.contrib.auth.forms import PasswordChangeForm

from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.shortcuts import render
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string


from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from django.contrib.sites.shortcuts import get_current_site


from functools import wraps
from django.shortcuts import redirect
from django.contrib.auth import REDIRECT_FIELD_NAME









# Create your views here.
class TestEmailView(View):
    def get(self, request):
        subject = 'Test Email'
        message = 'This is a test email sent from Django.'
        sender_email = settings.EMAIL_HOST_USER
        recipient_email = 'aya.mohamed.alahdal@gmail.com'  # Your email address

        try:
            # Send email
            send_mail(subject, message, sender_email, [recipient_email])
            return HttpResponse('Test email sent successfully!')
        except Exception as e:
            return HttpResponse(f'Error sending email: {e}')


def home(request):
    if request.user.is_authenticated:
        form = MeepForm(request.POST or None, request.FILES or None)
        if request.method == "POST":
            if form.is_valid():
                meep = form.save(commit=False)
                meep.user = request.user
                meep.save()
                messages.success(request, "Post published successfully.")
                return redirect('home')

        meeps = Meep.objects.all().order_by("-created_at")

        for meep in Meep.objects.filter(user=request.user):
            if Report.objects.filter(meep=meep).count() >= 5:
                meep.delete()

        return render(request, 'home.html', {"meeps": meeps, "form": form})
    else:
        meeps = Meep.objects.all().order_by("-created_at")
        return render(request, 'home.html', {"meeps": meeps})




def profile_list(request):
    if request.user.is_authenticated:
        profiles = Profile.objects.exclude(user=request.user)
        return render(request, 'profile_list.html', {"profiles": profiles})
    else:
        messages.success(request, "Login to access this page.")
        return redirect('home')

    

def unfollow(request, pk):
    if request.user.is_authenticated:
        # Get the profile to unfollow 
        profile = Profile.objects.get(user_id=pk)
        # Unfollow the user
        request.user.profile.follows.remove(profile)
        request.user.profile.save()

        messages.success(request, f"You have successfully unfollowed {profile.user.username}.")
        return redirect(request.META.get("HTTP_REFERER"))
    
    else:
        messages.success(request, "Login to access this page.")
        return redirect('home')



def follow(request, pk):
    if request.user.is_authenticated:
        profile = get_object_or_404(Profile, user_id=pk)
        
        # Check if the user is trying to follow themselves
        if request.user.profile == profile:
            messages.error(request, "You can't follow yourself.")
            return redirect('home')

        # Add the followed profile to the user's follows list
        request.user.profile.follows.add(profile)
        
        # Save the changes
        request.user.profile.save()

        # Create a notification for the user being followed
        # Retrieve the Meep instance associated with the follow action
        try:
            Notification.objects.create(
                receiver=profile.user,
                sender=request.user,
                type='follow',
                content=("{} started following you.").format(request.user.username),
                profile=profile,
            )
        except (IntegrityError, Exception) as e:
            messages.error(request, f"An error occurred while following: {e}")
            return redirect('home')

        messages.success(request, f"You have successfully followed {profile.user.username}.")
        return redirect('home')
    
    else:
       messages.success(request, "Login to access this page.")
       return redirect('home')

    

def profile(request, pk):
   if request.user.is_authenticated:
      
      profile = Profile.objects.get(user_id=pk)
      meeps = Meep.objects.filter(user_id=pk)

      if request.method == "POST":
         current_user_profile = request.user.profile
         action = request.POST['follow']

         if action == "unfollow":
            current_user_profile.follows.remove(profile)

         elif action == "follow":
             current_user_profile.follows.add(profile)
         current_user_profile.save()   
   

      return render(request, 'profile.html',{"profile":profile, "meeps":meeps, "pk": pk})
   else:
       messages.success(request, "Login to access this page.")
       return redirect('home')
   
def followers(request, pk):
    if request.user.is_authenticated:
        if request.user.id == pk:
            profiles = Profile.objects.get(user_id=pk)
            return render(request, 'followers.html', {"profiles": profiles})
        else:
            messages.success(request, "This is not your page.")
            return redirect('home')
    else:
        messages.success(request, "Login to access this page.")
        return redirect('home')

    
def follows(request, pk):
    if request.user.is_authenticated:
        if request.user.id == pk:
            profiles = Profile.objects.get(user_id=pk)
            return render(request, 'follows.html', {"profiles": profiles})
        else:
            messages.success(request, "This is not your page.")
            return redirect('home')
    else:
        messages.success(request, "Login to access this page.")
        return redirect('home')


logger = logging.getLogger(__name__)
def login_user(request):
    if request.method == "POST":
        username = request.POST.get('username')  # Use get method to avoid KeyError
        password = request.POST.get('password')  # Use get method to avoid KeyError
        user = authenticate(request, username=username, password=password)
        

        if user is not None:
            login(request, user)
            print("login")
            messages.success(request, "Login successful!")
            return redirect('home')
        else:
            messages.error(request, "Invalid username or password. Please try again.")
            print("invalid", username, password)
            return redirect('login')
    else:
        # If it's not a POST request, render the login page
        return render(request, 'login.html', {})

def logout_user(request):
    logout(request)
    messages.success(request, "Logout successful. Hope to see you soon.")
    return redirect('home')


# Assume this is part of your user registration process
def register_user(request):
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already exists.")
            elif User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists.")
            else:
                # Create user account but don't authenticate yet
                user = form.save(commit=True)
                user.set_password(form.cleaned_data['password1'])
                user.is_active = True  
                user.save()

                # Create and save email verification token
                EmailVerificationToken.create(user)

                # Send verification email
                send_verification_email(request, user)

                messages.success(request, "Registration successful! Please check your email to verify your account.")
                return redirect('home')
        else:
            # If form is not valid, display the form with errors
            error_message = "Invalid form. Please check the entered information:\n"
            for field, errors in form.errors.items():
                error_message += f"{field}: {', '.join(errors)}\n"
            messages.error(request, error_message)
            return render(request, "register.html", {'form': form})
    else:
        # Initialize the form with empty fields
        form = SignUpForm(initial={'username': '', 'password1': '', 'password2': ''})
      
    # Render the registration form
    return render(request, "register.html", {'form': form})


def send_verification_email(request, user):
    # Create an EmailVerificationToken object for the user
    token_obj = EmailVerificationToken.create(user)
    token = token_obj.token

    # Construct the verification link
    current_site = get_current_site(request)
    verification_link = reverse('verify_email', kwargs={'token': token})

    # Construct the email message
    email_subject = 'Verify your email address'
    email_body = f'Please click the following link to verify your email address: {request.build_absolute_uri(verification_link)}'

    # Send the email
    send_mail(email_subject, email_body, 'from@example.com', [user.email])



def unauthenticated_user(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Check if the user is already authenticated
        if request.user.is_authenticated:
            # Redirect authenticated users to the home page or any other appropriate URL
            return redirect('home')  # Adjust 'home' to your desired URL name
        # Call the original view function for unauthenticated users
        return view_func(request, *args, **kwargs)
    return wrapped_view



def verify_email(request, token):
    print("Token from URL:", token)
    
    # Retrieve the EmailVerificationToken object from the database
    token_obj = EmailVerificationToken.objects.filter(token=token).first()
    if token_obj:
        print("Token from database:", token_obj.token)
        
        # Compare tokens from URL and database
        if token == token_obj.token:
            print("Tokens match.")
            
            # Check if the token has expired (if applicable)
            if token_obj.expires_at > timezone.now():
                print("Token has not expired.")
                
                # Mark the user's email as verified
                user = token_obj.user
                user.email_verified = True  # Mark email as verified
                print("email verified", token_obj.user)
                user.save()
                
                # Attempt to log in the user
                login(request, user)
                
                messages.success(request, "Registration successful!.")
                return redirect('email_verified')
            else:
                # Token has expired
                messages.error(request, "Token has expired.")
                return redirect('invalid_token')
        else:
            # Tokens do not match
            messages.error(request, "Tokens do not match.")
            return redirect('invalid_token')
    else:
        # Token object not found in the database
        messages.error(request, "Token not found.")
        return redirect('invalid_token')


def email_verified(request):

    return render(request, 'email_verified.html')

def invalid_token(request):
    return render(request, 'invalid_token.html')

   
def update_user(request):
    if request.user.is_authenticated:
        current_user = User.objects.get(id=request.user.id)
        profile_user = Profile.objects.get(user__id=request.user.id)

        user_form = SignUpForm(request.POST or None, request.FILES or None, instance=current_user)
        profile_form = ProfilePicForm(request.POST or None, request.FILES or None, instance=profile_user)
        password_change_form = PasswordChangeForm(request.user)

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)

            # Check if the username has been changed
            if user_form.cleaned_data['username'] != current_user.username:
                user.username = user_form.cleaned_data['username']
                messages.info(request, "Username has been changed successfully!")

            # Check if the password meets the criteria
            password = user_form.cleaned_data.get('password')
            if password:
                if not password_valid(password):
                    messages.error(request, "Password cannot be similar to your other personal information.")
                    messages.error(request, "Password must be at least 8 characters long.")
                    messages.error(request, "Commonly used passwords are not allowed.")
                    messages.error(request, "Your password cannot be all numeric.")

            user.save()
            profile_form.save()

            login(request, current_user)
            messages.success(request, "Your profile has been updated successfully!")
            return redirect('home')

        return render(request, "update_user.html", {'user_form': user_form, 'profile_form': profile_form, 'password_change_form': password_change_form})
    else:
        messages.success(request, "You must log in to access this page!")
        return redirect('home')


def password_valid(password):
    # Check if the password contains at least 8 characters
    if len(password) < 8:
        return False

    # Check if the password is too common (you can define a list of common passwords)
    common_passwords = ['password', '123456', 'qwerty']
    if password.lower() in common_passwords:
        return False

    # Check if the password contains at least one letter and one digit
    if not re.search(r'\d', password) or not re.search(r'[a-zA-Z]', password):
        return False

    # Check if the password contains only alphanumeric characters
    if not password.isalnum():
        return False

    return True

    
def add_comment(request, pk):
    # Check if the user is authenticated
    if not request.user.is_authenticated:
        messages.error(request, "You must log in to comment.")
        return redirect('home')

    meep = get_object_or_404(Meep, id=pk)
    if request.method == 'POST':
        form = CommentForm(request.POST)
        if form.is_valid():
            comment_text = form.cleaned_data.get('body')
            mentioned_usernames = [word[1:] for word in comment_text.split() if word.startswith('@')]
            if comment_text.strip():
                comment = form.save(commit=False)
                comment.user = request.user
                comment.meep = meep
                comment.save()

                for username in mentioned_usernames:
                    content = f"{request.user.username} mentioned you in their post."
                    try:
                        user = User.objects.get(username=username)
                        Notification.objects.create(
                            receiver=user,
                            sender=request.user,
                            type='mention',
                            meep=meep,
                            content=content,
                            mentioned=True,  # Set mentioned to True
                        )
                    except User.DoesNotExist:
                        messages.error(request, f"The user {username} does not exist.")

                # Create a notification for the comment, only if the user is not commenting on their own post
                if request.user != meep.user:
                    content = f"{request.user.username} commented on your post."
                    Notification.objects.create(
                        receiver=meep.user,
                        sender=request.user,
                        type='comment',
                        meep=meep,
                        content=content,
                    )

                    comment_notifications = Notification.objects.filter(receiver=request.user, type='comment', read=False)
                    for notification in comment_notifications:
                        notification.read = True
                        notification.save()

                    mention_notifications = Notification.objects.filter(receiver=request.user, type='mention', read=False)
                    for notification in mention_notifications:
                        notification.read = True
                        notification.save()

                messages.success(request, "Your comment has been added successfully.")
                return redirect('meep_show', pk=pk)
            else:
                messages.error(request, "Empty comment.")
        else:
            messages.error(request, "Cannot submit an empty comment.")
    else:
        form = CommentForm()

    return render(request, 'show_meep.html', {'form': form, 'meep': meep})


def notifications(request):
    if request.user.is_authenticated:
        # Get all notifications for the current user
        notifications = Notification.objects.filter(receiver=request.user).order_by('-created_at')
        
        # Filter notifications that are new
        new_notifications = notifications.filter(is_new=True)
       
        return render(request, 'notifications.html', {'notifications': notifications, 'new_notifications': new_notifications})
        

    else:
        messages.success(request, "You must log in to access this page!")
        return redirect('home')

def meep_like(request, pk):
    if request.user.is_authenticated:
        # Check if the user is authenticated

        # Get the Meep object with the given primary key (pk)
        meep = get_object_or_404(Meep, id=pk)

        # Check if the user has already liked the Meep
        if meep.likes.filter(id=request.user.id):
            # If the user has already liked the Meep

            # Check if the user is not the owner of the Meep
            if request.user != meep.user:
                # If the user is not the owner of the Meep

                # Remove the user's like from the Meep
                meep.likes.remove(request.user)

                # Create a notification for the owner of the Meep
                content = f"{request.user.username} liked your post."
                Notification.objects.create(
                    receiver=meep.user,
                    sender=request.user,
                    type='like',
                    meep=meep,
                    content=content,
                )

                # Mark all like notifications as read for the current user
                like_notifications = Notification.objects.filter(receiver=request.user, type='like', read=False)
                for notification in like_notifications:
                    notification.read = True
                    notification.save()
            else:
                # If the user is the owner of the Meep

                # Remove the user's like from the Meep
                meep.likes.remove(request.user)
        else:
            # If the user has not already liked the Meep

            # Add the user's like to the Meep
            meep.likes.add(request.user)

        # Redirect the user back to the previous page
        #return redirect(request.META.get("HTTP_REFERER"))
     # Redirect the user to the same page with a fragment identifier to scroll to the same position
        return redirect(request.META.get("HTTP_REFERER") + '#meep_' + str(pk))
    else:
        # If the user is not authenticated

        # Redirect the user to the home page with a message
        messages.success(request, "You must log in to access this page!")
        return redirect('home')

    
def meep_show(request, pk):
    meep = get_object_or_404(Meep, id=pk)
    if meep:
        return render(request, "show_meep.html", {'meep': meep})
    else:
        messages.success(request, "This post does not exist!")
        return redirect('home')



def delete_meep(request, pk):
    if request.user.is_authenticated:
        meep = get_object_or_404(Meep, id=pk)
        # Check if you own the meep
        if request.user.username == meep.user.username:
            meep.delete()
            messages.success(request, "The post has been deleted.")
            return redirect(request.META.get("HTTP_REFERER"))
        else:
            messages.success(request, "Yes! This is not your post.")
            return redirect('home')
    else:
        messages.success(request, "You must be logged in first.")
        return redirect(request.META.get("HTTP_REFERER"))

    

def edit_meep(request, pk):
    if request.user.is_authenticated:
        meep = get_object_or_404(Meep, id=pk)
        # Check if the user owns the meep
        if request.user == meep.user:
            form = MeepForm(request.POST or None, request.FILES or None, instance=meep)
            if request.method == "POST":
                if form.is_valid():
                    meep = form.save(commit=False)
                    meep.user = request.user
                    meep.save()
                    messages.success(request, "Your post has been successfully updated.")
                    return redirect('home')
            else:
                return render(request, "edit_meep.html", {'form': form, 'meep': meep})
        else:
            messages.error(request, "You do not have permission to edit this post.")
            return redirect('home')
    else:
        messages.error(request, "You must be logged in first.")
        return redirect('home')

    

def delete_comment(request, pk):
    if request.user.is_authenticated:
        comment = get_object_or_404(Comment, id=pk)
        if request.user == comment.user:
            comment.delete()
            messages.success(request, "Comment deleted successfully.")
        else:
            messages.error(request, "You do not have permission to delete this comment.")
        return redirect(request.META.get("HTTP_REFERER"))
    else:
        messages.error(request, "You must be logged in first.")
        return redirect(request.META.get("HTTP_REFERER"))

def edit_comment(request, pk):
    if request.user.is_authenticated:
        comment = get_object_or_404(Comment, id=pk)
        meep = comment.meep 
        if request.user == comment.user:
            form = CommentForm(request.POST or None, instance=comment)
            if request.method == "POST":
                if form.is_valid():
                    comment.user = request.user
                    form.save()
                    messages.success(request, ("Comment updated successfully."))
                    return redirect('meep_show', pk=meep.pk)
            return render(request, "edit_comment.html", {'form': form, 'comment': comment, 'meep': meep})
        else:
            messages.error(request, ("You do not have permission to edit this comment."))
            return redirect(request.META.get("HTTP_REFERER"))
    else:
        messages.error(request, ("You must be logged in first."))
        return redirect(request.META.get("HTTP_REFERER"))


      

def search(request):
    if request.method == "POST":
         search = request.POST['search']
         # search the datebase
         searched = Meep.objects.filter(body__contains = search)
         return render(request, 'search.html', {'search':search, 'searched':searched})
    
    else:   
        return render(request, 'search.html', {})
              

def search_user(request):
    if request.method == "POST":
         search = request.POST['search']
         # search the datebase
         searched = User.objects.filter(username__contains = search)
         return render(request, 'search_user.html', {'search':search, 'searched':searched})
    
    else:   
        return render(request, 'search_user.html', {})   
    
def share_post_view(request, post_id):

    if not request.user.is_authenticated:
        messages.error(request, ("You must be logged in to share."))
        return redirect('home')
    
    meep = get_object_or_404(Meep, id=post_id)
    
    content = f"{request.user.username} shared your post."
    
    Notification.objects.create(
            receiver=meep.user,  # The original poster receives the notification
            sender=request.user,
            type='share',
            meep=meep,
            content=content,
        )
    
    share_notifications = Notification.objects.filter(receiver=request.user, type='share', read=False)
    for notification in share_notifications:
        notification.read = True
        notification.save()
        
    return render(request, 'share_post.html', {'meep': meep})


def get_unread_notification_count(request):
    if request.user.is_authenticated:
        unread_notification_count = Notification.objects.filter(receiver=request.user, read=False).count()
        return JsonResponse({'unread_notification_count': unread_notification_count})
    else:
        return JsonResponse({'unread_notification_count': 0})
    

def update_read_notifications(request):
    if request.user.is_authenticated:
        unread_notifications = Notification.objects.filter(receiver=request.user, read=False)
        unread_notifications.update(read=True)
        return JsonResponse({'success': True})
    else:
        return JsonResponse({'success': False})
    


def report_content(request, pk):
    if not request.user.is_authenticated:
        messages.error(request, ("You must be logged in to access this page."))
        return redirect('home')
    
    meep = Meep.objects.get(id=pk)
    if request.method == 'POST':
        form = AnonymousReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.meep = meep  # Assign the Meep instance to the report
            report.is_anonymous = True  # Mark the report as anonymous
            report.save()
            
            # Create a notification for the owner of the reported post
            Notification.objects.create(
                receiver=report.meep.user,
                sender=request.user,
                type='report',
                meep=report.meep,
                content=('Your post has been reported.'),
            )
            
            messages.success(request, ('Thank you for reporting! We will investigate the issue.'))
            return redirect('home')
    else:
        form = AnonymousReportForm()
    return render(request, 'report_content.html', {'form': form, 'meep': meep})

@login_required
def view_reports(request):
    # Filter reports based on the meep objects of the logged-in user
    user_reports = Report.objects.filter(meep__user=request.user)


    return render(request, 'view_reports.html', {'reports': user_reports})




def google_oauth(request):
    # Construct the authorization URL
    auth_url = 'https://accounts.google.com/o/oauth2/auth'
    auth_params = {
        'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
        'redirect_uri': 'http://localhost:8000/auth/google/callback',  # Your redirect URI
        'scope': 'openid email profile',  # Scopes required by your application
        'response_type': 'code',
    }
    redirect_url = f'{auth_url}?{"&".join([f"{key}={value}" for key, value in auth_params.items()])}'

    # Redirect the user to the OAuth consent screen
    return redirect(redirect_url)





def google_oauth_callback(request):
    # Extract authorization code from the request
    code = request.GET.get('code')

    # Exchange authorization code for access token
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
        'client_secret': settings.GOOGLE_OAUTH2_CLIENT_SECRET,
        'redirect_uri': 'http://localhost:8000/auth/google/callback',  # Your redirect URI
        'grant_type': 'authorization_code',
    }
    response = requests.post(token_url, data=token_data)
    token_info = response.json()

    # Log token_info response for debugging
    print("Token Info Response:", token_info)

    # Check if access token is present
    if 'access_token' in token_info:
        # Use access token to retrieve user information
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {token_info["access_token"]}'}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        # Authenticate user in Django application
        user = authenticate(google_id=user_info['id'])

        if user is not None:
            # If user exists, log them in
            login(request, user)
            return redirect('protected_page')
        else:
            # If user does not exist, create a new account
            # You may need to adjust this based on your user model structure
            new_user = User.objects.create_user(username=user_info['email'], email=user_info['email'])
            new_user.save()
            
            # Log in the newly created user
            login(request, new_user)
            return redirect('protected_page')
    else:
        # Handle error response from Google
        messages.error(request, "Failed to obtain access token from Google.")
        return redirect('google_oauth_failure')


def protected_page_view(request):
    # Add any necessary logic for rendering the protected page
    return render(request, 'protected_page.html')


def google_oauth_failure_view(request):
    return render(request, 'google_oauth_failure.html')


def password_reset_request(request):
    if request.method == "POST":
        email = request.POST['email']
        user = User.objects.filter(email=email).first()
        if user is not None:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', args=[uid, token]))
            send_password_reset_email(user.email, reset_url)
        # Display a success message or redirect the user to a confirmation page
    return render(request, 'password_reset_form.html')

def send_password_reset_email(email, reset_url):
    subject = 'Reset your password'
    message = render_to_string('password_reset_email.html', {
        'reset_url': reset_url,
    })
    send_mail(subject, message, None, [email])





def custom_404(request, exception):
    return render(request, '404.html', status=404)


def about_page(request):
    return render(request, 'about.html')



def privacy_policy(request):
    return render(request, 'privacy_policy.html')

def terms_of_service(request):
    return render(request, 'terms_of_service.html')

