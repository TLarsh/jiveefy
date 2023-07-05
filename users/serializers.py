import profile
from urllib import request
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
from django.contrib.auth.hashers import check_password

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


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'username',
            'fullname',
            'lastname',
            'bio',
            'phone_number',
            'city',
            'country_name',
            'password',
            'created_at',
            'updated_at'
        )
        
 
class UserPodcastSerializer(serializers.ModelSerializer):
    post_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('username', 'plan', 'status', 'post_count')

    def get_post_count(self, user):
        return user.post_set.count()    
       
       
class AdminUserSerialaizer(serializers.ModelSerializer):
    # podcast = PodcastSerializer(many=True)
    class Meta:
        model = User        
        fields = (
            "id",
            "email",
            "username",
            
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
        
        
        


from rest_framework import serializers
# from django.contrib.auth.models import User


# serializers.py


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only =True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    class Meta:
       model = User
       fields = ['fullname', 'lastname', 'email', 'current_password', 'new_password']
       extra_kwargs = {
           'email': {'required': True}
       }




# class UserProfileUpdateSerializer(serializers.ModelSerializer):
    # new_password = serializers.CharField(write_only=True, required=False)
    # current_password = serializers.CharField(write_only=True, required=False)

    # class Meta:
    #    model = User
    #    fields = ['fullname', 'lastname', 'email', 'current_password', 'new_password']
    #    extra_kwargs = {
    #        'email': {'required': True}
    #    }
    
    # def validate_current_password(self, user):
    #     user = self.context['request'].user
    #     if not user.check_password(user):
    #         raise serializers.ValidationError('Current password is incorrect.')
    #     return user

    # def validate(self, attrs):
    #     current_password = attrs.get('current_password')
    #     new_password = attrs.get('new_password')

    #     if current_password and not new_password:
    #         raise serializers.ValidationError('New password is required.')

    #     if new_password and not current_password:
    #         raise serializers.ValidationError('Current password is required.')

    #     return attrs

    # def update(self, instance, validated_data):
    #     current_password = validated_data.get.pop('current_password')
    #     new_password = validated_data.get('new_password')

    #     if current_password and new_password:
    #         instance.set_password(new_password)
    #         # instance.save()

    #     return super().update(instance, validated_data)

    # class Meta:
    #     model = User
    #     fields = ['first_name', 'last_name', 'email', 'current_password', 'new_password']
    #     extra_kwargs = {
    #         'email': {'required': True}
    #     }

# class UserProfileUpdateSerializer(serializers.ModelSerializer):
#     user = UserSerializer(required=False)
#     current_password = serializers.CharField(write_only=True, required=False)
#     delete_picture_id = serializers.BooleanField(write_only=True, required=False)

#     class Meta:
#         model = UserProfile
#         fields = ('user', 'fullname', 'lastname', 'image', 'current_password', 'delete_picture_id')

#     def validate(self, attrs):
#         request = self.context['request']
#         user = request.user
#         current_password = attrs.get('current_password')

#         if current_password and not user.check_password(current_password):
#             raise serializers.ValidationError("Current password is incorrect.")

#         return attrs

#     def update(self, instance, validated_data):
#         user_data = validated_data.pop('user', None)
#         fullname = validated_data.get('fullname')
#         lastname = validated_data.get('lastname')
#         # picture_id = validated_data.get('picture_id')
#         image = validated_data.get('image')
#         current_password = validated_data.get('current_password')
#         delete_picture_id = validated_data.get('delete_picture_id', False)

#         if user_data:
#             user = instance.user
#             user.email = user_data.get('email', user.email)
#             user.username = user_data.get('username', user.username)
#             new_password = user_data.get('password')

#             if new_password:
#                 user.set_password(new_password)

#             user.save()

#         if fullname is not None:
#             instance.fullname = fullname
#         if lastname is not None:
#             instance.lastname = lastname
#         # if picture_id is not None:
#             # instance.picture_id = picture_id
#         if delete_picture_id:
#             instance.picture_id = None
#             instance.image.delete(save=False)
#         if image is not None:
#             instance.image = image

#         instance.save()
#         return instance




class UserProfileUpdateSerializer(serializers.ModelSerializer):
    # profile = UserProfileSerializer(required=False)
    current_password = serializers.CharField(write_only=True, required=False)
    delete_image = serializers.BooleanField(write_only=True, required=False)

    class Meta:
        model = User
        fields = (
            'email',
            'username',
            'fullname',
            'lastname',
            'bio',
            'phone_number',
            'city',
            'country_name',
            'current_password',
            'password',
            'image',
            'delete_image'
        )
        
        
    def validate(self, attrs):
        request = self.context['request']
        user = request.user
        current_password = attrs.get('current_password')

        if current_password and not user.check_password(current_password):
            raise serializers.ValidationError("Current password is incorrect.")

        return attrs

    def update(self, instance, validated_data):
        # user = self.context[request].user
        email = validated_data.get('email', instance.email)
        username = validated_data.get('username', instance.username)
        fullname = validated_data.get('fullname', instance.fullname)
        lastname = validated_data.get('lastname', instance.lastname)
        city = validated_data.get('city', instance.city)
        phone_number = validated_data.get('phone_number', instance.phone_number)
        country_name = validated_data.get('country_name', instance.country_name)
        bio = validated_data.get('bio', instance.bio)
        image = validated_data.get('bio', instance.image)
        delete_image = validated_data.get('delete_image', False)
        password = validated_data.get('password', instance.password)



        if email is not None:
            instance.email=email
        if username is not None:
            instance.username = username
        if fullname is not None:
            instance.fullname = fullname
        if lastname is not None:
            instance.lastname = lastname
        if city is not None:
            instance.city = city
        if bio is not None:
            instance.bio = bio
        if phone_number is not None:
            instance.phone_number = phone_number  
        if country_name is not None:
            instance.country_name = country_name
        if image is not None:
            instance.image = image
        if delete_image:
           instance.delete_image = None
           instance.image.delete(save=False)
            
        new_password = password
        if new_password:
            instance.set_password(new_password)
         
        instance.save()
        return instance