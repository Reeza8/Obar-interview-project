from datetime import timedelta
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import status
from User.models import Ban  # مسیر مدل‌ها را متناسب با پروژه خود اصلاح کنید

def check_ban(phone_number, ip):
    """
    بررسی بن بودن شماره تلفن یا آی‌پی.
    اگر بن فعال باشد، Response با خطا برمی‌گرداند.
    اگر بن بیش از یک ساعت باشد، رکوردهای بن حذف می‌شوند و None برمی‌گرداند.
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)
    ban_qs = Ban.objects.filter(string__in=[phone_number, ip]).order_by('-createdAt')

    if ban_qs.exists():
        ban_record = ban_qs.first()
        if ban_record.createdAt < one_hour_ago:
            ban_qs.delete()
            return None
        else:
            return Response({'message': 'شما به مدت یک ساعت بن شده‌اید.'}, status=status.HTTP_403_FORBIDDEN)
    return None
