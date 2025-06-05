import uuid
from django.contrib.auth import get_user_model

User = get_user_model()

def generate_unique_username(base_username):
    username = base_username or str(uuid.uuid4())[:30]
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}_{counter}"
        counter += 1
    return username
