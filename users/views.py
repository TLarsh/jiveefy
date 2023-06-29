from configparser import NoOptionError
from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth import get_user_model

from appjiviefy.models import Podcast
from appjiviefy.serializers import PodcastSerializer
User = get_user_model()
from rest_framework.response import Response
from . import serializers
from django.utils.encoding import force_bytes
from base64 import urlsafe_b64decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import Util
from django.urls import reverse

from rest_framework.views import APIView
from rest_framework import permissions, status
from users.serializers import(
    AdminUserSerialaizer,
    ResetPasswordEmailRequestSerializer,
    UserSerialaizer,
    LogoutSerializer
)
from rest_framework.generics import(
    ListAPIView,
    GenericAPIView,
    RetrieveUpdateDestroyAPIView
)


# Create your views here.

class SignupView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, format=None):
        data = self.request.data
    
        email = data['email']
        username = data['username']
        password = data['password']
        password2 = data['confirm password']
        
        if password == password2:
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error":"User with specified email already exists"},
                    status = status.HTTP_400_BAD_REQUEST
                )
            elif User.objects.filter(username=username).exists():
                return Response(
                    {"error":"Not available, try new username"},
                    status = status.HTTP_400_BAD_REQUEST
                )
            else:
                if len(password) < 8:
                    return Response({'error':'Password must be more than 8 characters'})
                else:
                    user = User.objects.create_user(email=email, password=password, username=username)
                    user.save()
                    return Response({'success':f'Account successfully created for {email}'})
        else:
            return Response({'error':'password not matched'})
        
        
        

# Requests the registered email to password reser

class PasswordResetView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.EmailSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data["email"]
        user = User.objects.filter(email=email).first()
        if user:
            encoded_pk = urlsafe_base64_encode (force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            reset_url = reverse(
                "reset-password",
                kwargs = {
                    "encoded_pk":encoded_pk,
                    "token":token
                }
            )
                
            reset_url = f"localhost:8000{reset_url}"
            return Response(
                {
                    "message":f"Your password reset link: {reset_url}"
                },
                status = status.HTTP_200_OK,
            )
                
        else:
            return Response(
                {"message":"User doesnt exists"},
                status = status.HTTP_400_BAD_REQUEST
            )
            
       
class ResetPassword(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = serializers.ResetPasswordSerializer
    def patch(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"kwargs":kwargs}
        )
        
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "Password reset complete"},
            status=status.HTTP_200_OK,
        )
                

                    
class UserView(RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = User.objects.all()
    serializer_class = (UserSerialaizer)
    
class UsersView(ListAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = (UserSerialaizer)
    
class LogoutAPIView(GenericAPIView):
    serializer_class = (LogoutSerializer)
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

# Admin Acess
    
class UserCountView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request):
        user_count = User.objects.count()
        return Response({'total': user_count})
    

class ActiveUserCountView(APIView):
    def get(self, request):
        active_user_count = User.objects.filter(is_active=True).count()
        return Response({'actives': active_user_count})
    

class UserAdminView(ListAPIView):
    permission_classes = (permissions.AllowAny,)
    def get(self, request):
        # Retrieve all users
        users = User.objects.all()

        # Serialize the users
        serialized_users = AdminUserSerialaizer(users, many=True).data

        # Fetch posts for each user
        for user in serialized_users:
            posts = Podcast.objects.filter(user_id=user['id'])
            serialized_posts = PodcastSerializer(posts, many=True).data
            user['posts'] = serialized_posts

        return Response(serialized_users)
    
# class UserActionView(APIView):
#     def get(self, request, user_id):
#         # Retrieve the user based on the provided user_id
#         user = User.objects.get(id=user_id)

#         # Count the number of posts for the user
#         post_count = Podcast.objects.filter(user=user).count()
#         serializer = AdminUserSerialaizer

#         # Return the post count as a response
#         return Response({'post_count': post_count}, serializer.data)
