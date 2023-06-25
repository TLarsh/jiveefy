from rest_framework import serializers
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode



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
            "email",
            "email",
            
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
        
    
        