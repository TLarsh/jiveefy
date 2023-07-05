
from django.urls import path
from django.urls import path, re_path
from stripe import Account
from .views import(
    AccountActivationView,
    # ChangePasswordView,
    LogoutAPIView,
    PasswordResetView,
    ResetPassword,
    SignupView,
    UserAdminView,
    UserPodcastlists,
    UserView,
    UsersView,
    UserCountView,
    ActiveUserCountView,
    UserProfileUpdateView,
    UserProfileDetailView,
    # ChangePasswordView
)


urlpatterns = [
    
    path('profile/', UserProfileDetailView.as_view()),
    path('podcasters/', UserPodcastlists.as_view()),
    path('update/', UserProfileUpdateView.as_view()),
    path('update/<pk>/', UserProfileUpdateView.as_view(), name='update-profile'),
    # path('change-password/', ChangePasswordView.as_view(), name='change-password'),

    # path('update/', UserProfileUpdateView.as_view(), name='user-profile-update'),
    path('count/', UserCountView.as_view(), name='user-count'),
    path('actives/', ActiveUserCountView.as_view(), name='active-user-count'),
    path('signup', SignupView.as_view(), name='signup'),
    path('activate/<str:encoded_pk>/<str:token>/', AccountActivationView.as_view(), name='activate'),
    # path('signup/', RegistrationView.as_view(), name='register'),
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
    
    
