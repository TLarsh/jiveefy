from rest_framework import serializers
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from appjiviefy.models import Podcast



User = get_user_model()


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
            
            
            
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    class Meta:
        fields = ['email',]
        
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
        
        
        



        
    
        