import requests
from rest_framework.views import APIView
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from json import JSONDecodeError

from blog.password import NAVER_ID, NAVER_PW
from .utils import social_user_get_or_create
from .authenticate import jwt_login

User = get_user_model()

BASE_URL = 'http://127.0.0.1:8000/'
NAVER_CALLBACK_URI = BASE_URL + 'market/naver/callback/'

class NaverLoginApi(APIView):
    def get(self, request, *args, **kwargs):
        client_id = NAVER_ID
        return redirect(f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={client_id}&state=STATE_STRING&redirect_uri={NAVER_CALLBACK_URI}")

class NaverSigninCallBackApi(APIView):
    def get(self, request, *args, **kwargs):
        client_id = NAVER_ID
        client_secret = NAVER_PW
        code = request.GET.get("code")
        state_string = request.GET.get("state")

        # code로 access token 요청
        token_request = requests.get(f"https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&state={state_string}")
        token_response_json = token_request.json()

        error = token_response_json.get("error", None)
        if error is not None:
            raise JSONDecodeError(error) # type: ignore

        access_token = token_response_json.get("access_token")

        # access token으로 네이버 프로필 요청
        profile_request = requests.post(
            "https://openapi.naver.com/v1/nid/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_info = profile_request.json()
        print(user_info)
        profile_data = {
            'username': user_info['response'].get('email'),
            'image': user_info["response"].get('profile_image', ''),
            'name': user_info['response'].get('name', ''),
            'nickname': user_info['response'].get('nickname', ''),
            'path': "naver",
        }
        
        user, _ = social_user_get_or_create(**profile_data)
        respone = jwt_login(user=user)
        
        return respone