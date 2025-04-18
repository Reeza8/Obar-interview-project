from rest_framework_simplejwt.views import TokenRefreshView
from User.models import User, VerifyCode, Ban, RequestCount
import random
from datetime import timedelta
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from User.serializers.serializer import CheckRegistrationSerializer, VerifyCodeSerializer
from django.db import transaction
from common.utils import check_ban


class UserViewSet(viewsets.ViewSet):

    @action(methods=['post'], detail=False, url_path='checkRegistration')
    def checkRegistration(self, request):
        # Validate input using serializer
        serializer = CheckRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phoneNumber']
        ip = self.get_client_ip(request)

        # Check if phone number or IP is banned
        ban_response = check_ban(phone_number, ip)
        if ban_response:
            return ban_response

        # Check if user with this phone number and status=1 exists
        if User.objects.filter(phoneNumber=phone_number, status=1).exists():
            return Response({'message': 'رمز را وارد کنید.'})

        # Check if a verification code has been sent in the last 2 minutes
        two_minutes_ago = timezone.now() - timedelta(minutes=2)
        recent_code = VerifyCode.objects.filter(
            phoneNumber=phone_number,
            isUsed=0,
            createdAt__gte=two_minutes_ago
        ).first()

        if recent_code:
            return Response({'message': 'کد تایید کمتر از 2 دقیقه پیش ارسال شده است.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Generate new verification code
        code = ''.join([str(random.randint(0, 9)) for _ in range(5)])
        VerifyCode.objects.create(phoneNumber=phone_number, code=code, isUsed=0)

        # TODO: Send verification code via SMS

        return Response({
            'message': 'کد تایید ارسال شد.',
            'code': code  # Return code for debugging
        })

    # verifyCode endpoint
    @action(methods=['post'], detail=False, url_path='verifyCode')
    def verifyCode(self, request):
        # Validate input using serializer
        serializer = VerifyCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phoneNumber']
        code = serializer.validated_data['code']
        ip = self.get_client_ip(request)

        # Check if phone number or IP is banned
        ban_response = check_ban(phone_number, ip)
        if ban_response:
            return ban_response

        # Check for a valid and unused verification code
        valid_code_qs = VerifyCode.objects.filter(
            phoneNumber=phone_number,
            code=code,
            isUsed=0
        )
        if valid_code_qs.exists():
            # If code is valid, check if user exists
            user_qs = User.objects.filter(phoneNumber=phone_number)
            if user_qs.exists():
                user = user_qs.first()
            else:
                # Create new user with status=0 if not exists
                user = User.objects.create(phoneNumber=phone_number, status=0)

            # Mark the verification code as used
            valid_code_qs.update(isUsed=1)

            # TODO: Generate and return authentication token
            token = user.generate_token()
            refresh = user.generate_refreshtoken()
            return Response({
                'message': 'کد تایید صحیح میباشد. لطفا اطلاعات هویتی را تکمیل کنید',
                'token': token,
                'refresh': refresh,
                'user_id': user.id
            }, status=status.HTTP_200_OK)



        # Check failed attempts for phone number and IP
        phone_req_count = RequestCount.objects.filter(string=phone_number, type="1").count()
        ip_req_count = RequestCount.objects.filter(string=ip, type="1").count()

        banned_entities = []

        with transaction.atomic():
            # If phone number has 2 or more failed attempts, ban and delete related records
            if phone_req_count >= 2:
                Ban.objects.create(string=phone_number)
                RequestCount.objects.filter(string=phone_number, type="1").delete()
                banned_entities.append('شماره تلفن ')

            # If IP has 2 or more failed attempts, ban and delete related records
            if ip_req_count >= 2:
                Ban.objects.create(string=ip)
                RequestCount.objects.filter(string=ip, type="1").delete()
                banned_entities.append(' آی‌پی')

        if banned_entities:
            # Build response message based on banned entities
            message = 'و'.join(banned_entities) + ' شما به مدت یک ساعت بلاک شده است.'
            return Response({'message': message}, status=status.HTTP_403_FORBIDDEN)

        # If neither is banned, add new failed attempt records
        RequestCount.objects.create(string=phone_number, type="1")
        RequestCount.objects.create(string=ip, type="1")

        return Response({'message': 'کد تایید صحیح نمیباشد'}, status=status.HTTP_400_BAD_REQUEST)

    # Utility to get client IP address
    def get_client_ip(self, request):
        # Extract client IP address from headers or remote address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip



class TokenRefreshAPIView(TokenRefreshView):
    pass
