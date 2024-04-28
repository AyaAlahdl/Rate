
from datetime import datetime
from .token_generator import generate_unique_token_for_user
from .models import EmailVerificationToken

  # Adjust the import path as needed


#def is_valid_verification_token(token, user):
    # Check if the token exists and hasn't expired
    #token_obj = EmailVerificationToken.objects.filter(token=token, user=user).first()
    #if not token_obj:
        #return False  # Token doesn't exist
    
    # Check if the token has expired
    #current_time = datetime.now()
    #if token_obj.expires_at < current_time:
        #return False  # Token has expired
    
    # Token exists and hasn't expired
    #return True


#def mark_email_as_verified(user):
    #user.is_email_verified = True
    #user.save()

