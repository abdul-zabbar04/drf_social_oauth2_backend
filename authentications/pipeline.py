def set_user_role_and_provider(strategy, details, backend, user=None, *args, **kwargs):
    """
    Custom pipeline step to:
    - Set auth_provider based on backend name (e.g., google-oauth2)
    - Set role as 'attendee'
    - Remove unusable password for social users
    """
    if user:
        # Only update if using a social backend
        if backend.name == 'google-oauth2':
            user.auth_provider = 'google'
        elif backend.name == 'linkedin-openidconnect':
            user.auth_provider = 'linkedin'
            user.username= user.email
        user.role = 'attendee'

        # Clear unusable password if login via social
        user.set_unusable_password()
        user.save()

