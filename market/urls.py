from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import routers
from .views import *
from auth.googleapi import *
from auth.kakaoapi import *
from auth.naverapi import *

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
    path("post/<int:pk>/comments/<int:comment_pk>/", CommentManageApi.as_view(), name='comment-detail'),
    path("post/<int:pk>/comments/<int:comment_pk>/reply/<int:reply_pk>/", ReplyManageApi.as_view(), name='reply-detail'),
    path("auth/<int:user_id>/update/", UpdateProfileApi.as_view()),
    
    # 구글 소셜로그인
    path('google/login/', GoogleloginApi.as_view(), name='google_login'),
    path('google/callback/', GoogleSinginCallbackApi.as_view(), name='google_callback'),
    # path('google/login/finish/', GoogleLogin.as_view(), name='google_login_todjango'),
    
    # 카카오 소셜로그인
    path('kakao/login/', KakaologinApi.as_view(), name='kakao_login'),
    path('kakao/callback/', KakaaoSigninCallBackApi.as_view(), name='kakao_callback'),
    # path('kakao/login/finish/', KakaoLogin.as_view(), name='kakao_login_todjango'),
    
    # 네이버 소셜로그인
    path('naver/login', NaverLoginApi.as_view(), name='naver_login'),
    path('naver/callback/', NaverSigninCallBackApi.as_view(), name='naver_callback'),
    # path('naver/login/finish/', NaverLogin.as_view(), name='naver_login_todjango'),
]