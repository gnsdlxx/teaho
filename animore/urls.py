from django.urls import path
from . import views
from .views import SignupView, UserProfileSetupView, UserProfileUpdateView, ReviewListCreateView

urlpatterns = [
    path("signup/", views.SignupView.as_view()),
    path('login/', views.Login),
    path("<int:pk>/", views.user_detail), #이거가 약간 뭐랄까 유정 정보에 관한 거 같은데 그럼 유저 프로필 인걸까 그럼 이거는 필요가 없는데
    path('activate/<str:uid>/<str:token>',views.UserActivateView.as_view(), name ='activate'),
    path('findid/',views.findemail),
    path("profile/", views.MeView.as_view()),
    path('profile/setup/', UserProfileSetupView.as_view(), name='profile-setup'),
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),
    path('reviews/', ReviewListCreateView.as_view(), name='review-list-create'),
    path('reviews/<int:pk>/', views.ReviewDetailUpdateDeleteView.as_view(), name='review-detail-update-delete'),
]