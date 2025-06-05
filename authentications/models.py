from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    AUTH_PROVIDER_CHOICES = (
        ('email', 'Email'),
        ('google', 'Google'),
        ('linkedin', 'LinkedIn'),
    )

    ROLE_CHOICES = (
        ('attendee', 'Attendee'),
        ('organizer', 'Organizer'),
    )

    auth_provider = models.CharField(
        max_length=20,
        choices=AUTH_PROVIDER_CHOICES,
        default='email'
    )
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='attendee'
    )

    def save(self, *args, **kwargs):
        if self.auth_provider in ['google', 'linkedin']:
            self.role = 'attendee'
        super().save(*args, **kwargs)
