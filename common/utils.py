import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework.exceptions import NotAuthenticated, AuthenticationFailed, ValidationError

def custom_exception_handler(exc, context):
    # Let DRF handle the exception first
    response = exception_handler(exc, context)

    if response is not None:
        # Handle authentication errors with Persian messages
        if isinstance(exc, NotAuthenticated):
            response.data = {'detail': 'اطلاعات لازم برای احراز هویت ارسال نشده است.'}
        elif isinstance(exc, AuthenticationFailed):
            response.data = {'detail': 'احراز هویت ناموفق است.'}

        # Handle validation errors for email field
        elif isinstance(exc, ValidationError):
            # Check if 'email' field is in the errors
            if 'email' in response.data:
                # Replace the error messages for email with Persian message
                response.data['email'] = ['آدرس ایمیل وارد شده معتبر نیست.']

    return response

def decode_and_validate_token(request):
    # Get the Authorization header from the request
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header:
        return None, 'هدر احراز ارسال نشده است'

    parts = auth_header.split()
    # Check if the header is in the correct format: "Bearer <token>"
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None, 'فرمت هدر احراز صحیح نیست'

    token = parts[1]

    try:
        # Decode and verify the token using the SECRET_KEY and HS256 algorithm
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return None, 'شناسه کاربر در توکن یافت نشد'
        return user_id, None

    except ExpiredSignatureError:
        return None, 'توکن منقضی شده است'
    except InvalidTokenError:
        return None, 'توکن نامعتبر است'

def get_client_ip(request):
    # Extract client IP address from headers or remote address
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip