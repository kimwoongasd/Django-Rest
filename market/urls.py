from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import routers
from .views import *

router = routers.DefaultRouter()
router.register('list', UserViewSet) # 유저리스트 (테스트용)

urlpatterns = [
    path('hello/', HelloAPI),
    path("", include(router.urls)),
    path("register/", RegisterAPIView.as_view()), #회원가입하기
    path("auth/", Authview.as_view()), #로그인하기
    path("auth/refresh/", TokenRefreshView.as_view()), #토큰 재발급하기
    path("post/", PostList.as_view()),
    path("post/<int:pk>/", PostDetail.as_view()),
    
    # 구글 소셜로그인
    path('google/login/', google_login, name='google_login'),
    path('google/callback/', google_callback, name='google_callback'),
    path('google/login/finish/', GoogleLogin.as_view(), name='google_login_todjango'),
]