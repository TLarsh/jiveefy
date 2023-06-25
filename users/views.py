from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from . import serializers
from django.utils.encoding import force_bytes, smart_str, smart_bytes, DjangoUnicodeDecodeError
from base64 import urlsafe_b64decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from .utils import Util
from django.urls import reverse

User = get_user_model()
from rest_framework.views import APIView
from rest_framework import permissions, status
from users.serializers import(
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
                return Response('user already exists')
            else:
                if len(password) < 6:
                    return Response({'error':'Password must be more than 6 characters'})
                else:
                    user = User.objects.create_user(email=email, password=password, username=username)
                    user.save()
                    return Response({'success':f'Account successfully created for {email}'})
        else:
            return Response({'error':'password not matched'})
        


# class PasswordResetView(GenericAPIView):
#     serializer_class = serializers.EmailSerializer
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         email = serializer.data["email"]
#         user = User.objects.filter(email=email).first()
#         if user:
#             encoded_pk = urlsafe_b64decode (force_bytes(user.pk))
#             token = PasswordResetTokenGenerator().make_token(User)

#             reset_url = reverse(
#                 "reset-password",
#                 kwargs = {
#                     "encoded_pk":encoded_pk,
#                     "token":token
#                 }
#             )
                
#             reset_url = f"localhost:8000{reset_url}"
#             return Response(
#                 {
#                     "message":f"Your password reset link: {reset_url}"
#                 },
#                 status = status.HTTP_200_ok,
#             )
                
#             else:
                
                
class RequestPasswordEmailResetView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = ResetPasswordEmailRequestSerializer
    def post(self, request):
        data = {'request':request, 'data':request.data}
        serializer = self.serializer_class(data=data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objeccts.get(email=email)
            uidb64 = urlsafe_base64_encode(user.id)
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request.domain)
            relativeLink = reverse('password-resit-confirm', kwargs={'uidb64':uidb64, 'token':token})
            absurl = 'http://'+current_site+relativeLink+ relativeLink + relativeLink
            email_body = "Hi "+user.username+' Use link below to reset your password \n' + absurl
            data = {'email_body':email_body, 'to_email':user.email,
                    'email_subject':'Reset your password'}
            print(data)      
            Util.send_email(data)
        return Response({'Success': "Password reser link is now sent to your mail", status:status.HTTP_200_OK})
        
class PasswordTokenCheckAPI(GenericAPIView):
    def get(self, request, uidb64, token0):
        pass
        
    


                



                    
class UserView(RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = User.objects.all()
    serializer_class = (UserSerialaizer)
    
class UsersView(ListAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = (UserSerialaizer)
    
class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    