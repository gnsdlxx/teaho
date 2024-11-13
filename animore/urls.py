from django.urls import path
from . import views
from .views import SignupView, UserProfileSetupView, UserProfileUpdateView

urlpatterns = [
    path("signup/", views.SignupView.as_view()),
    path('login/', views.Login),
    path("<int:pk>/", views.user_detail),
    path('activate/<str:uid>/<str:token>',views.UserActivateView.as_view(), name ='activate'),
    path('findid/',views.findemail),
    path("profile/", views.MeView.as_view()),
    path('profile/setup/', UserProfileSetupView.as_view(), name='profile-setup'),
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),
]