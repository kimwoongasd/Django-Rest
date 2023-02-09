from django.db import transaction
from django.contrib.auth import get_user_model
from market.models import Profile

User = get_user_model()

@transaction.atomic
def social_user_create(username, password=None, **extra_fields):
    user = User(username=username, email=username)
    if password:
        user.set_password(password)
    else:
        user.set_unusable_password()
    # user.full_clean()
    user.save()
    
    profile = Profile(user=user)
    
    try:
        profile.prfile_pic = extra_fields['image']
    except:
        pass
    
    if extra_fields['nickname'] == '':
       profile.nickname = username.split("@")[0]
    else:
       profile.nickname = extra_fields['nickname']
    
    if extra_fields['name'] != "":
        profile.realname = extra_fields['name']
    
    # try:
    #     try:
    #         user.first_name = extra_fields['first_name'] 
    #         user.last_name = extra_fields['last_name']
    #     except:
    #         try:
    #             user.first_name = extra_fields['name']
    #         except:
    #             pass
    # except:
    #     pass
    
    try:
        path = extra_fields['path']
        profile.provier = f"{path}"
    except:
        pass
    
    profile.save()
    
    return user


@transaction.atomic
def social_user_get_or_create(username, **extra_data):
    user = User.objects.filter(email=username).first()

    if user:
        return user, False
    
    return social_user_create(username=username, **extra_data), True