from django.contrib import admin
from .models import CustomUser
from django.contrib import admin
from django.contrib.sessions.models import Session

admin.site.register(Session)


admin.site.register(CustomUser)