import datetime, jwt
import blog.settings as settings
from django.http import JsonResponse


def generate_access_token(user):
    access_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(
            days=0, minutes=60
        ),
        'iat': datetime.datetime.utcnow(),
    }
    
    access_token = jwt.encode(
        access_token_payload,
        settings.SECRET_KEY, algorithm='HS256'
    )
    
    return access_token
    
    
def generate_refresh_token(user):
    refresh_token_payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }
    
    refresh_token = jwt.encode(
        refresh_token_payload,
        settings.SECRET_KEY, algorithm='HS256'
    )
    
    return refresh_token


def jwt_login(user):
    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)
    
    data = {
        'access_token': access_token,
        'refresh_token' : refresh_token
    }
    
    response = JsonResponse(data)
    return response