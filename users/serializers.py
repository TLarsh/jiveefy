from rest_framework import serializers
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site


from appjiviefy.models import Podcast



User = get_user_model()

# class RegistrationSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(
#         max_length=128,
#         min_length=8,
#         write_only=True
#     )
#     token = serializers.SerializerMethodField()
    
#     class Meta:
#         model = User
#         fields = ['username', 'email', 'password', 'token']

#     # def get_token(self, obj):
#     #     refresh = RefreshToken.for_user(obj)
#     #     return {
#     #         'refresh': str(refresh),
#     #         'access': str(refresh.access_token),
#     #     }

#     def create_user(self, validated_data):
#         username = validated_data['username'],
#         email = validated_data['email'],
#         password = validated_data['password']
#         password2 = validated_data['confirm password']
#         if password == password2:
#             if User.objects.filter(email=email).exists():
#                 raise serializers.ValidationError(
#                     "User with specified email already exists"
#                 )
#             elif User.objects.filter(username=username).exists():
#                 raise serializers.ValidationError(
#                     "Not available, try new username"
                    
#                 )
#             else:
#                 if len(password) < 8:
#                     raise serializers.ValidationError('Password must be more than 8 characters')
#                 else:
#                     user = User.objects.create_user(email=email, password=password, username=username)
#                     user.save()
#                     current_site = get_current_site(self.context['request'])
#                     uid = urlsafe_base64_encode(force_bytes(user.pk))
#                     token = RegistrationTokenGenerator().make_token(user)

#                     verification_link = reverse('email-verify', kwargs={'uidb64': uid, 'token': token})
#                     email_subject = 'Account Activation'
#                     email_message = f'Hi {user.username},\n\nPlease click the following link to activate your account:\n\n{verification_link}\n\nThank you.'
#                     # return (email_message)
#                     # sendEmail = self.send_verification_email(user)
#                     return (user, email_message)
#         else:
#             raise serializers.ValidationError('password not matched')
#         # user = User.objects.create_user(
#         #     username,
#         #     email,
#         #     password
#         # )
#         # user.is_active = False
#         # user.save()
#         # self.send_verification_email(user)
#         # return user

#     def send_verification_email(self, user):
#         current_site = get_current_site(self.context['request'])
#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#         token = RegistrationTokenGenerator().make_token(user)

#         verification_link = reverse('email-verify', kwargs={'uidb64': uid, 'token': token})
#         email_subject = 'Account Activation'
#         email_message = f'Hi {user.username},\n\nPlease click the following link to activate your account:\n\n{verification_link}\n\nThank you.'
#         return (email_message)

#         # BaseEmailMessage(
#         #     subject=email_subject,
#         #     body=email_message,
#         #     from_email='your_email@example.com',
#         #     to=[user.email],
#         # ).send()

# class RegistrationTokenGenerator:
#     def make_token(self, user):
#         return urlsafe_base64_encode(force_bytes(user.pk))

#     def check_token(self, user, token):
#         return urlsafe_base64_encode(force_bytes(user.pk)) == token


class UserSerialaizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "fullname",
            "lastname",
            "phone_number",
            "city",
            "bio",
            "picture_id",
            
        )

class PodcastSerializer(serializers.ModelSerializer):
    class Meta:
        model = Podcast.objects.count()
        fields = (
            "user",
        )
       
       
class AdminUserSerialaizer(serializers.ModelSerializer):
    # podcast = PodcastSerializer(many=True)
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "fullname",
            "lastname",
            "phone_number",
            "city",
            "bio",
            "picture_id",
            # "podcast",  
    
            
        )
      
        
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token=attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad token')
            
            
# SERIALIZER TO MAKE A RESET TOKEN         
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    class Meta:
        fields = ['email',]
        
        
# SERIALIZER  PASSWORD RESET      
class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8
    )
    confirm_password = serializers.CharField(
        write_only=True,
        min_length=8
    )
    
    class Meta:
        fields = ("password",)
        
    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data")
        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)
        
        if password == confirm_password:
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Invalid reset token passed")

        else:
            raise serializers.ValidationError("password not match")
        user.set_password(password)
        user.save()
        return data
    
    
    
class AccountActivationSerializer(serializers.Serializer):
       
    def validate(self, data):
        
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data")
        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)

        if not self.RegistrationTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Invalid activation token passed")

        
        user.is_staff=True
        user.save()
        return data
    
    class RegistrationTokenGenerator:
        def make_token(self, user):
            return urlsafe_base64_encode(force_bytes(user.pk))

        def check_token(self, user, token):
            return urlsafe_base64_encode(force_bytes(user.pk)) == token
            
        

            
# class ResetPasswordEmailSerializer(serializers.Serializer):
#     email = serializers.EmailField(min_length=2)

#     class Meta:
#         fields = ['email']

#     def validate(self, attrs):
#         try:
#             email = attrs.get('email', '')
#             if User.objects.filter(email=email).exists():
#                 user=User.objects.filter(email=email)
#                 uidb64=urlsafe_base64_encode(user.id)
#                 token = PasswordResetTokenGenerator().make_token(user)
#             return attrs
#         except expression as identifier:
#             pass
#         return super().validate(attrs)
    
    
class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']
        
        
        



        
    
        