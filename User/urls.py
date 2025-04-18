from rest_framework.routers import DefaultRouter
from User.Api.userApi import UserViewSet,TokenRefreshAPIView
from django.urls import path

app_name = 'User'
routers = DefaultRouter()


routers.register(r'userApi', UserViewSet, basename='user')
urlpatterns = [path('token/refresh/', TokenRefreshAPIView.as_view(), name='token_refresh'), ] + routers.urls

