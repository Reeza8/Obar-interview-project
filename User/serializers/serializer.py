from rest_framework import serializers
from django.core.validators import RegexValidator

phone_regex = RegexValidator(
    regex=r'^(?:\+98|0)?9\d{9}$',
    message="شماره تلفن باید با +98 یا 0 شروع شود و 10 رقم بعد از آن داشته باشد."
)

class CheckRegistrationSerializer(serializers.Serializer):
    phoneNumber = serializers.CharField(
        max_length=14,
        validators=[phone_regex],
        required=True,
        help_text='شماره تلفن'
    )
class VerifyCodeSerializer(serializers.Serializer):
    phoneNumber = serializers.CharField(
        required=True,
        help_text='شماره تلفن'
    )
    code = serializers.CharField(required=True,max_length=5)
