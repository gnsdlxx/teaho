from django.urls import path
from . import views
from .views import SignupView

urlpatterns = [
    path("signup/", views.SignupView.as_view()),
    path('login/', views.Login),
    path("<int:pk>/", views.user_detail),
    path("profile/", views.MeView.as_view()),
    path('activate/<str:uid>/<str:token>',views.UserActivateView.as_view(), name ='activate'),
    path('findid/',views.findemail),
]