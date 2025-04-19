from django.db import models
from django.core.validators import RegexValidator
import jwt
from django.core.validators import MinLengthValidator
from datetime import datetime, timedelta
from ObarInterviewProject.settings import SECRET_KEY
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import status


phone_regex = RegexValidator(regex=r'^(\+98?)?{?(0?9[0-9]{9,9}}?)$')

class User(models.Model):
    name = models.CharField(max_length=255, null=True, help_text='نام')
    lastName = models.CharField(max_length=255, null=True, help_text='نام خانوادگی')
    email = models.EmailField(max_length=255, unique=True, null=True, help_text='ایمیل')
    password = models.CharField(max_length=255, null=True, validators=[MinLengthValidator(8)], help_text='رمز')
    phoneNumber = models.CharField(validators=[phone_regex], max_length=14, unique=True,
                                   help_text='شماره تلفن')
    modifiedAt = models.DateTimeField(auto_now=True, help_text='زمان اصلاح شدن')
    status = models.PositiveSmallIntegerField(default=0, help_text='وضعیت')
    createdAt = models.DateTimeField(auto_now_add=True, help_text='زمان ایجاد شدن')

    REQUIRED_FIELD = ['phoneNumber',]

    def generate_token(self):
        payload = {
            'user_id': self.id,
            'name': self.name,
            'phoneNumber': self.phoneNumber,
            'lastName': self.lastName,
            "token_type": "access",
            "exp": (datetime.now() + timedelta(days=10)).timestamp(),
            "iat": datetime.now().timestamp(),
            "jti": "4304b89444f448b3a34b4a112c876d0e",
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def generate_refreshtoken(self):
        payload = {
            'user_id': self.id,
            'name': self.name,
            'lastName': self.lastName,
            'phoneNumber': self.phoneNumber,
            "token_type": "refresh",
            "exp": (datetime.now() + timedelta(days=60)).timestamp(),
            "iat": datetime.now().timestamp(),
            "jti": "4304b89444f448b3a34b4a112c876d0e",
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

class VerifyCode(models.Model):
    code = models.CharField(max_length=5, help_text='کد تایید')
    phoneNumber = models.CharField(max_length=17, help_text='شماره تلفن')
    isUsed = models.PositiveSmallIntegerField(default=0, help_text='استفاده شده')
    createdAt = models.DateTimeField(auto_now_add=True, help_text='زمان ایجاد شدن')

class RequestCount(models.Model):
    Type_CHOICES = (
        ("0", "login"),
        ("1", "verifyCode"),
    )
    string = models.CharField(max_length=5, help_text='ایپی یا شماره تلفن')
    createdAt = models.DateTimeField(auto_now_add=True, help_text='زمان ایجاد شدن')
    type = models.CharField(max_length=11, choices=Type_CHOICES, help_text='نوع درخواست')

class Ban(models.Model):
    string = models.CharField(max_length=255, help_text='ایپی یا شماره تلفن')
    bannedUntil = models.DateTimeField(help_text='زمان پایان بن')

    @classmethod
    def check_ban(cls, phone_number, ip):
        """
        Check if phone number or IP is banned.
        Delete expired ban records.
        Return Response with remaining ban time if active ban exists, else None.
        """

        # Check if both inputs are missing or empty
        if not phone_number and not ip:
            return Response(
                {'message': 'شماره تلفن یا آی‌پی برای بررسی بن ارسال نشده است.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        now = timezone.now()

        # Prepare list of valid strings to check

        # Delete expired bans (where bannedUntil passed)
        cls.objects.filter(string__in=[phone_number, ip], bannedUntil__lte=now).delete()

        # Check for active ban
        active_ban = cls.objects.filter(string__in=[phone_number, ip], bannedUntil__gt=now).first()
        if active_ban:
            remaining_seconds = int((active_ban.bannedUntil - now).total_seconds())
            remaining_minutes = remaining_seconds // 60 + 1  # Round up to next minute
            return Response(
                {'message': f'شما به مدت {remaining_minutes} دقیقه به دلیل تلاش‌های ناموفق بن شده‌اید.'},
                status=status.HTTP_403_FORBIDDEN
            )

        return None

