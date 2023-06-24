# from unicodedata import decimal
from django.db import models
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class UserAccountManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        if not email:
            raise ValueError('User must have an emil')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, email, username, password):
        user = self.create_user(email, username, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user
        

class UserAccount(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, null=True, blank=True)
    fullname = models.CharField(max_length=150, null=True, blank=True)
    lastname = models.CharField(max_length=150, null=True, blank=True)
    phone_number = models.CharField(max_length=50, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    bio = models.TextField(max_length=500, null=True, blank=True)
    picture_id = models.ImageField(max_length=500, null=True, blank=True)
    is_active = models.BooleanField(default=True, )
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    
    
    objects = UserAccountManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
    def get_full_name(self):
        return self.username
    def get_short_name(self):
        return self.username
    
    