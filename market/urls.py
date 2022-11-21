from django.urls import path
from .views import HelloAPI, RegisterAPIView, Authview

urlpatterns = [
    path('hello/', HelloAPI),
    path("register/", RegisterAPIView.as_view()), #회원가입하기
    path("auth/", Authview.as_view()), #로그인하기
]