
from django.urls import path
from django.urls import path, re_path
from stripe import Account
from .views import(
    LogoutAPIView,
    # PasswordResetView,
    RequestPasswordEmailResetView,
    PasswordTokenCheckAPI,
    SignupView,
    UserView,
    UsersView,
)


urlpatterns = [
    path('signup', SignupView.as_view()),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-email/', RequestPasswordEmailResetView.as_view(), name='request-reset-email'),
    # path('password-reset', PasswordResetView.as_view()),
    # path('password-reset/<str:encoded_pk>/<str:token>/', 
        #  PasswordResetView.as_view(), 
        #  name='reset-password'),
    path('', UsersView.as_view()),
    path('<pk>/', UserView.as_view()),
    path('<pk>/update', UserView.as_view()),
    path('logout/', LogoutAPIView.as_view())
]