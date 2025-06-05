from django.urls import path
from .views import GoogleLoginSessionView, LinkedInLoginView, LogoutView, CurrentUserView

urlpatterns = [
    path('auth/google/session-login/', GoogleLoginSessionView.as_view(), name='google-session-login'),
    path('auth/linkedin/', LinkedInLoginView.as_view(), name='linkedin-login'),
    path('auth/me/', CurrentUserView.as_view(), name='current-user'),
    path('logout/', LogoutView.as_view(), name='logout'),
]

