from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('drf_social_oauth2.urls', namespace='drf')),
    path('auth/', include('social_django.urls', namespace='social')),
    path('', include('authentications.urls'))
]
