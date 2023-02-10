import requests
from rest_framework.views import APIView
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from json import JSONDecodeError

from blog.password import KAKAO_ID
from .utils import social_user_get_or_create
from .authenticate import jwt_login

User = get_user_model()

BASE_URL = 'http://127.0.0.1:8000/'
KAKAO_CALLBACK_URI = BASE_URL + 'market/kakao/callback/'

class KakaologinApi(APIView):
    def get(self, request, *args, **kwargs):
        client_id = KAKAO_ID
        kakao_auth = "https://kauth.kakao.com/oauth/authorize?response_type=code"
        scope = "account_email, profile_image, profile_nickname"
        return redirect(f"{kakao_auth}?client_id={client_id}&redirect_uri={KAKAO_CALLBACK_URI}&response_type=code&scope={scope}")
    
    
class KakaaoSigninCallBackApi(APIView):
    def get(self, request, *args, **kwargs):
        client_id = KAKAO_ID
        code = request.GET.get("code")
        
        token_request = requests.post(f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={KAKAO_CALLBACK_URI}&code={code}")
        token_response_json = token_request.json()
        
        # 에러 발생 시 중단
        error = token_response_json.get("error", None)
        if error is not None:
            raise JSONDecodeError(error)  # type: ignore

        access_token = token_response_json.get("access_token")
        profile_request = requests.post(
            "https://kapi.kakao.com/v2/user/me",
            headers={
                "Authorization": f"Bearer {access_token}"
                },
            )
        user_info= profile_request.json()
        
        profile_data = {
            'username': user_info['kakao_account'].get('email'),
            'image': user_info['kakao_account'].get('profile_image', ''),
            'name': user_info['kakao_account'].get('profile_nickname', ''),
            'nickname': user_info['kakao_account'].get('profile_nickname', ''),
            'path': "kakao",
            
        }
        print(profile_data)
        user, _ = social_user_get_or_create(**profile_data)
        respone = jwt_login(user=user)
        print()
        print(respone)
        return respone