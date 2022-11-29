from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import routers
from .views import HelloAPI, RegisterAPIView, Authview, UserViewSet

router = routers.DefaultRouter()
router.register('list', UserViewSet) # 유저리스트 (테스트용)

urlpatterns = [
    path('hello/', HelloAPI),
    path("", include(router.urls)),
    path("register/", RegisterAPIView.as_view()), #회원가입하기
    path("auth/", Authview.as_view()), #로그인하기
    path("auth/refresh/", TokenRefreshView.as_view()), #토큰 재발급하기
]