from rest_framework_simplejwt.views import TokenRefreshView
from User.models import User, VerifyCode, Ban, RequestCount
import random
from datetime import timedelta
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from User.serializers.userSerializer import CheckRegistrationSerializer, VerifyCodeSerializer,CompleteRegistrationSerializer, LoginSerializer
from django.db import transaction
from common.utils import decode_and_validate_token, get_client_ip
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from ObarInterviewProject import settings

class UserViewSet(viewsets.ViewSet):

    @action(methods=['post'], detail=False, url_path='checkRegistration')
    def check_registration(self, request):
        # Validate input using serializer
        serializer = CheckRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phoneNumber']
        ip = get_client_ip(request)

        # Check if phone number or IP is banned
        ban_response = Ban.check_ban(phone_number, ip)
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


    @action(methods=['post'], detail=False, url_path='verifyCode')
    def verify_code(self, request):
        # Validate input using serializer
        serializer = VerifyCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phoneNumber']
        code = serializer.validated_data['code']
        ip = get_client_ip(request)

        # Check if phone number or IP is banned
        ban_response = Ban.check_ban(phone_number, ip)
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

            token = user.generate_token()
            refToken = user.generate_refreshtoken()
            return Response({
                'message': 'ثبت نام با موفقیت انجام شد',
                'access': token,
                'refresh': refToken,
                'user_id': user.id
            }, status=status.HTTP_200_OK)

        # Check failed attempts for phone number and IP
        phone_req_count = RequestCount.objects.filter(string=phone_number, type="1").count()
        ip_req_count = RequestCount.objects.filter(string=ip, type="1").count()

        banned_entities = []

        ban_time = getattr(settings, 'BAN_TIME', 1)  # Ban duration in hours, default 1 hour

        with transaction.atomic():
            # If phone number has 2 or more failed attempts, ban and delete related records
            if phone_req_count >= 2:
                Ban.objects.create(
                    string=phone_number,
                    bannedUntil=timezone.now() + timedelta(hours=ban_time)
                )
                RequestCount.objects.filter(string=phone_number, type="1").delete()
                banned_entities.append('شماره تلفن ')

            # If IP has 2 or more failed attempts, ban and delete related records
            if ip_req_count >= 2:
                Ban.objects.create(
                    string=ip,
                    bannedUntil=timezone.now() + timedelta(hours=ban_time)
                )
                RequestCount.objects.filter(string=ip, type="1").delete()
                banned_entities.append(' آی‌پی')

        if banned_entities:
            # Build response message based on banned entities
            message = ' و '.join(banned_entities) + ' شما به مدت یک ساعت بلاک شد'
            return Response({'message': message}, status=status.HTTP_403_FORBIDDEN)

        # If neither is banned, add new failed attempt records
        RequestCount.objects.create(string=phone_number, type="1")
        RequestCount.objects.create(string=ip, type="1")

        return Response({'message': 'کد تایید صحیح نمی‌باشد.'}, status=status.HTTP_400_BAD_REQUEST)


    @action(methods=['put'], detail=False, url_path='completeRegistration')
    def complete_registration(self, request):
        # Validate the incoming data using serializer
        serializer = CompleteRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Decode and validate JWT token to get user_id
        user_id, error = decode_and_validate_token(request)
        if error:
            return Response({'detail': error}, status=status.HTTP_401_UNAUTHORIZED)

        # Try to get the user object from database
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'کاربر یافت نشد.'}, status=status.HTTP_404_NOT_FOUND)

        # Update user information and hash the password
        user.name = serializer.validated_data['name']
        user.lastName = serializer.validated_data['lastName']
        user.email = serializer.validated_data['email']
        user.password = make_password(serializer.validated_data['password'])  # Hash the password
        user.status = 1
        user.save()

        return Response({'message': 'اطلاعات با موفقیت بروزرسانی شد.'}, status=status.HTTP_200_OK)


    @action(methods=['post'], detail=False, url_path='login')
    def login(self, request):
        # Validate input using serializer
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phoneNumber']
        password = serializer.validated_data['password']
        ip = get_client_ip(request)

        # Check if IP or phone number is banned using the model method
        ban_response = Ban.check_ban(None, ip)
        if ban_response:
            return ban_response

        # Try to find user with phoneNumber and status=1
        user = User.objects.filter(phoneNumber=phone_number, status=1).first()

        if user and check_password(password, user.password):
            # Successful login: clear login attempts for this IP
            RequestCount.objects.filter(string=ip, type="0").delete()

            access_token = user.generate_token()
            refresh_token = user.generate_refreshtoken()

            return Response({
                'message': 'ورود با موفقیت انجام شد',
                'access': access_token,
                'refresh': refresh_token,
                'user_id': user.id
            }, status=status.HTTP_200_OK)

        # Login failed - count attempts and ban if needed
        with transaction.atomic():
            attempts = RequestCount.objects.filter(string=ip, type="0").count()

            if attempts >= 2:
                # Ban IP for 1 hour
                BAN_TIME_HOURS = getattr(settings, 'BAN_TIME_HOURS', 1)  # Default 1 hour

                Ban.objects.create(string=ip, bannedUntil=timezone.now() + timedelta(hours=BAN_TIME_HOURS))
                # Delete all attempts for this IP
                RequestCount.objects.filter(string=ip, type="0").delete()
                return Response({'message': 'شما به مدت یک ساعت به دلیل تلاش‌های ناموفق بن شده‌اید.'},
                                status=status.HTTP_403_FORBIDDEN)

            # Add new failed login attempt record
            RequestCount.objects.create(string=ip, type="0")

        return Response({'message': 'شماره تلفن یا رمز عبور اشتباه است.'}, status=status.HTTP_400_BAD_REQUEST)


class TokenRefreshAPIView(TokenRefreshView):
    # TO DO (not asked in test)
    pass


