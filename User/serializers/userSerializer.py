from rest_framework import serializers
from django.core.validators import RegexValidator
import re

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

def validate_password(value):
    if len(value) < 8:
        raise serializers.ValidationError("رمز عبور باید حداقل ۸ کاراکتر باشد.")
    if value.isdigit():
        raise serializers.ValidationError("رمز عبور نمی‌تواند فقط شامل عدد باشد.")
    if not re.search(r'[A-Za-z]', value):
        raise serializers.ValidationError("رمز عبور باید شامل حداقل یک حرف باشد.")
    if not re.search(r'\d', value):
        raise serializers.ValidationError("رمز عبور باید شامل حداقل یک عدد باشد.")
    return value

class CompleteRegistrationSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255, required=True, help_text='نام')
    lastName = serializers.CharField(max_length=255, required=True, help_text='نام خانوادگی')
    email = serializers.EmailField(max_length=255, help_text='ایمیل')
    password = serializers.CharField(
        required=True,
        write_only=True,
        help_text='رمز عبور',
        validators=[validate_password]
    )

class LoginSerializer(serializers.Serializer):
    phoneNumber = serializers.CharField(max_length=14)
    password = serializers.CharField(write_only=True, min_length=8)