from django.shortcuts import render
from django.contrib.auth import get_user_model
from rest_framework.response import Response

User = get_user_model()
from rest_framework.views import APIView
from rest_framework import permissions, status
from users.serializers import(
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
    