# backends.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        '''print('Arrived at backend authenticate method')

        # Print all users in the database for debugging purposes
        all_users = User.objects.all()
        print('All users in database:')
        for user in all_users:
            print(f'User: {user.email}, Name: {user.name}, Role: {user.role}')

        # Check the MongoDB collection name
        collection_name = User._meta.db_table  # This should give you the MongoDB collection name
        print(f'Collection name: {collection_name}')'''

        # Clean email input
        email = email.strip() if email else None

        try:
            user = User.objects.get(email__iexact=email)
            print('Found user:', user)
        except User.DoesNotExist:
            print(f'User with email {email} does not exist')
            return None
        
        print('Attempting to check password')
        if user.check_password(password):
            print('Password verified')
            return user
        else:
            print('Password incorrect')
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
