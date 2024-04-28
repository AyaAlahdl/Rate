import secrets

# This dictionary simulates a database of users and their tokens
user_tokens = {}

def generate_unique_token_for_user(user):
    # Generate a random token using secrets module
    token = secrets.token_urlsafe(20)
    # Associate the token with the user in the database
    user_tokens[user] = token
    return token

# Example usage
#user = "example_user"
#token = generate_unique_token_for_user(user)
#print("Generated token for user", user, ":", token)
#print("User token database:", user_tokens)
