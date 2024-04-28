from django.test import TestCase

# Create your tests here.
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from app.models import EmailVerificationToken
from app.utils import generate_unique_token_for_user

class EmailVerificationTokenTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='password123')

    def test_token_generation(self):
        # Test if a token is generated for a user
        token = generate_unique_token_for_user(self.user)
        self.assertIsNotNone(token)

    def test_token_verification(self):
        # Create a token and save it to the database
        token = generate_unique_token_for_user(self.user)
        expiration_time = timezone.now() + timezone.timedelta(days=1)
        EmailVerificationToken.objects.create(user=self.user, token=token, expires_at=expiration_time)

        # Verify the token
        verified_user = EmailVerificationToken.verify_token(token)
        self.assertEqual(verified_user, self.user)

        # Verify invalid token
        invalid_user = EmailVerificationToken.verify_token('invalid_token')
        self.assertIsNone(invalid_user)

        # Verify expired token
        expired_token = generate_unique_token_for_user(self.user)
        expired_token_obj = EmailVerificationToken.objects.create(user=self.user, token=expired_token, expires_at=timezone.now() - timezone.timedelta(days=1))
        expired_user = EmailVerificationToken.verify_token(expired_token)
        self.assertIsNone(expired_user)
        self.assertTrue(expired_token_obj.has_expired())

    def test_email_verification_link_generation(self):
        # Test if the email verification link is generated correctly
        token = generate_unique_token_for_user(self.user)
        link = EmailVerificationToken.generate_verification_link(token)
        self.assertIsNotNone(link)
        self.assertIn(token, link)

    def test_email_verification_email_sending(self):
        # Test if the verification email is sent successfully
        token = generate_unique_token_for_user(self.user)
        EmailVerificationToken.send_verification_email(self.user, token)
        # Add assertions to check if the email is sent (mocking may be required)

    # Add more test cases as needed
