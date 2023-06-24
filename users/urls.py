
from django.urls import path
from django.urls import path, re_path
from stripe import Account
from .views import(
    LogoutAPIView,
    SignupView,
    UserView,
    UsersView,
)


urlpatterns = [
    path('signup', SignupView.as_view()),
    path('', UsersView.as_view()),
    path('<pk>/', UserView.as_view()),
    path('<pk>/update', UserView.as_view()),
    path('logout/', LogoutAPIView.as_view())
]