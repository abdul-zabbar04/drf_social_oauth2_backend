from django.contrib.auth import login, logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from social_django.utils import load_backend, load_strategy
from social_core.exceptions import AuthException
from django.contrib.auth import get_user_model
from rest_framework import permissions
import requests
from django.conf import settings
from django.core.exceptions import ValidationError


from django.contrib.auth import login
from django.http import JsonResponse
from django.middleware.csrf import get_token  # <-- MOD
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import AuthException
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response

User = get_user_model()

class GoogleLoginSessionView(APIView):
    def post(self, request):
        access_token = request.data.get("access_token")
        if not access_token:
            return Response({"error": "No access token provided"}, status=400)

        strategy = load_strategy(request)
        backend = load_backend(strategy=strategy, name='google-oauth2', redirect_uri=None)

        try:
            user = backend.do_auth(access_token)
        except AuthException:
            return Response({"error": "Authentication failed"}, status=400)

        if user:
            if not user.is_active:
                return Response({"error": "User is inactive"}, status=403)

            existing_user = User.objects.filter(email=user.email).first()
            if existing_user and existing_user.pk != user.pk:
                return Response({"error": "Duplicate email conflict"}, status=400)

            if not user.auth_provider:
                user.auth_provider = 'google'
                user.save()

            if user.auth_provider != 'google':
                return Response({"error": f"Please log in using {user.auth_provider}"}, status=400)

            login(request, user)

            response = JsonResponse({"message": "Logged in successfully with session"})
            response.set_cookie(  # <-- MOD
                key="csrftoken",
                value=get_token(request),  # <-- MOD
                httponly=False,
                secure=True,  # <-- MOD: should be True in production (HTTPS)
                samesite="Lax"
            )
            return response  # <-- MOD: send csrf token as cookie
        else:
            return Response({"error": "Invalid access token"}, status=400)

class LinkedInLoginView(APIView):
    def post(self, request):
        code = request.data.get('code')
        redirect_uri = request.data.get('redirect_uri')

        if not code or not redirect_uri:
            return Response({'error': 'Missing code or redirect_uri'}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Exchange code for access_token from LinkedIn
        token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': settings.SOCIAL_AUTH_LINKEDIN_OPENIDCONNECT_KEY,
            'client_secret': settings.SOCIAL_AUTH_LINKEDIN_OPENIDCONNECT_SECRET,
        }

        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()

        if 'access_token' not in token_json:
            return Response({'error': 'Failed to obtain access token', 'details': token_json}, status=400)

        access_token = token_json['access_token']

        # 2. Let social-auth handle the rest: user lookup, creation, linking, token saving
        strategy = load_strategy(request)
        backend = load_backend(strategy=strategy, name='linkedin-openidconnect', redirect_uri=redirect_uri)

        try:
            user = backend.do_auth(access_token)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'LinkedIn authentication failed', 'details': str(e)}, status=500)

        if user and user.is_active:
            login(request, user)

            # Set CSRF token manually
            csrf_token = get_token(request)

            social = user.social_auth.filter(provider='linkedin-openidconnect').first()
            extra_data = social.extra_data if social else {}

            response = Response({
                'message': 'Login successful',
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'tokens': {
                    'access_token': extra_data.get('access_token'),
                    'refresh_token': extra_data.get('refresh_token'),
                    'expires_in': extra_data.get('expires'),
                    'id_token': extra_data.get('id_token'),
                }
            })

            response.set_cookie('csrftoken', csrf_token, httponly=False, samesite='Lax')
            return response

        return Response({'error': 'Authentication failed'}, status=400)

# from django.contrib.auth import logout
# from django.http import JsonResponse
# from django.views import View

# class LogoutView(View):
#     def post(self, request):
#         logout(request)
#         response = JsonResponse({'message': 'Logged out successfully'})
#         response.delete_cookie('csrftoken')
#         return response

from django.contrib.auth import logout
from django.http import JsonResponse
from django.views import View

class LogoutView(View):
    def post(self, request, *args, **kwargs):
        logout(request)
        response = JsonResponse({'detail': 'Logout successful'})
        response.delete_cookie('sessionid')  # Optional: explicitly clear session cookie
        response.delete_cookie('csrftoken', path='/')
        return response

    def get(self, request, *args, **kwargs):
        return JsonResponse({'detail': 'Method not allowed'}, status=405)



class CurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        })

