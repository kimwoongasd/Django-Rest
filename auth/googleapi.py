import requests
from json import JSONDecodeError
from rest_framework.views import APIView
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from blog.password import *
from .utils import *
from .authenticate import *

User = get_user_model()
state = STATE
BASE_URL = 'http://127.0.0.1:8000/'
GOOGLE_CALLBACK_URI = BASE_URL + 'market/google/callback/'

class GoogleloginApi(APIView):
    def get(self, request, *args, **kwargs):
        scope = "https://www.googleapis.com/auth/userinfo.email" + \
                'https://www.googleapis.com/auth/userinfo.profile'
        client_id = GOOGLE_ID
        
        response = redirect(
            f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={GOOGLE_CALLBACK_URI}&scope={scope}"
        )
        return response

class GoogleSinginCallbackApi(APIView):
    def get(self, request, *args, **kwargs):
        client_id = GOOGLE_ID
        client_secret = GOOGLE_PW
        code = request.GET.get('code')
        
        # access token 요청
        token_response = requests.post(f"https://oauth2.googleapis.com/token?client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_CALLBACK_URI}&state={state}")
        
        token_response_json = token_response.json()
        error = token_response_json.get("error")
        
        # 에러 발생시 중단
        if error is not None:
            raise JSONDecodeError(error) # type: ignore
        
        # access token을 받는다
        access_token = token_response_json.get("access_token")
        
        # access token을 이용하여 유저 정보 가져오기
        user_info_response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            params={
            'access_token': access_token
            }
            )
        
        # 에러 발생시 중단
        if not user_info_response.ok:
            raise ValueError("Failed to obtain user info from Google")
        
    
        user_info = user_info_response.json()
        # print(user_info)
        profile_data = {
            'username' : user_info['email'],
            'first_name' : user_info.get('family_name', ''),
            'last_name': user_info.get('given_name', ''),
            'nickname': user_info.get('nickname', ''),
            'name': user_info.get('name', ''),
            'image': user_info.get('picture', None),
            'path': "google",
        }
        # print(profile_data)
        # 유저 정보를 이용하여 소셜유저 생성 및 프로필 생성
        user, _ = social_user_get_or_create(**profile_data)
        
        # 로그인
        respone = jwt_login(user=user)
        print(respone)
        return respone
            