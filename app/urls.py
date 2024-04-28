from . import views
from .views import share_post_view, get_unread_notification_count, TestEmailView, google_oauth, google_oauth_callback
from django.urls import path
from django.contrib.auth import views as auth_views



urlpatterns = [
    path('', views.home, name="home"),
    path('about/', views.about_page, name='about'),
    path('auth/google/', google_oauth, name='google_oauth'),
    path('auth/google/callback/', google_oauth_callback, name='google_oauth_callback'),
    path('profile_list', views.profile_list, name="profile_list"),
    path('profile/<int:pk>', views.profile, name="profile"),
    path('profile/followers/<int:pk>', views.followers, name="followers"),
    path('profile/follows/<int:pk>', views.follows, name="follows"),
    path('notifications/', views.notifications, name='notifications'),
    path('login/', views.login_user, name="login"),
    path('logout/', views.logout_user, name="logout"),
    path('register/', views.register_user, name="register"),
    path('update_user/', views.update_user, name="update_user"),
    path('meep_like/<int:pk>', views.meep_like, name="meep_like"),
    path('meep_show/<int:pk>', views.meep_show, name="meep_show"),
    path('Unfollow/<int:pk>', views.unfollow, name="unfollow"),
    path('follow/<int:pk>', views.follow, name="follow"),
    path('delete_meep/<int:pk>', views.delete_meep, name="delete_meep"),
    path('delete_comment/<int:pk>', views.delete_comment, name="delete_comment"),
    path('edit_meep/<int:pk>', views.edit_meep, name="edit_meep"),
    path('edit_comment/<int:pk>', views.edit_comment, name="edit_comment"),
    path('search/', views.search, name="search"),
    path('search_user/', views.search_user, name="search_user"),
    path('add_comment/<int:pk>/', views.add_comment, name='add_comment'),
    path('share/<int:post_id>/', share_post_view, name='share_post'),
    path('get_unread_notification_count/', get_unread_notification_count, name='get_unread_notification_count'),
    path('update_read_notifications/', views.update_read_notifications, name='update_read_notifications'),
    path('report_content/<int:pk>', views.report_content, name='report_content'),
    path('view_reports/', views.view_reports, name='view_reports'),
    path('protected-page/', views.protected_page_view, name='protected_page'),
    path('google-oauth-failure/', views.google_oauth_failure_view, name='google_oauth_failure'),
   
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset_form.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('terms-of-service/', views.terms_of_service, name='terms_of_service'),

    path('verify/<str:token>/', views.verify_email, name='verify_email'),
    path('email-verified/', views.email_verified, name='email_verified'),
    path('invalid-token/', views.invalid_token, name='invalid_token'),
]
 


