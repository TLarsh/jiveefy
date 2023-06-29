
from django.urls import path
from django.urls import path, re_path
from stripe import Account
from .views import(
    LogoutAPIView,
    PasswordResetView,
    ResetPassword,
    SignupView,
    UserAdminView,
    UserView,
    UsersView,
    UserCountView,
    ActiveUserCountView
)


urlpatterns = [
    path('count/', UserCountView.as_view(), name='user-count'),
    path('actives/', ActiveUserCountView.as_view(), name='active-user-count'),
    path('signup', SignupView.as_view(), name='signup'),
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/<str:encoded_pk>/<str:token>/', 
         ResetPassword.as_view(), 
         name='reset-password'),
    path('list/', UserAdminView.as_view(), name='list-action'),
    path('', UsersView.as_view(), name='users'),
    path('<pk>/', UserView.as_view(), name='user'),
    path('<pk>/update', UserView.as_view(), name='update'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    
    
]