from django.db import models, transaction
from django.core import validators
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from django.conf import settings
# Create your models here.
@deconstructible
class UnicodeUsernameValidator(validators.RegexValidator):
    regex = r'^[\w.@+-]+\Z'
    message = _(
        'Enter a valid username. This value may contain only letters, '
        'numbers, and @/./+/-/_ characters.'
    )
    flags = 0


class UserManager(BaseUserManager):
    @transaction.atomic
    def create_user(self, validate_data):
        username = validate_data["username"]
        email = validate_data["email"]
        password = validate_data["password"]
        first_name = validate_data['first_name']
        last_name = validate_data['last_name']
        
        if not username:
            raise ValueError('아이디는 필수 항목입니다.')
        if not email:
            raise ValueError('이메일은 필수 항목입니다.')
        if not password:
            raise ValueError('패드워드는 필수 항목입니다.')
        
        
        user = self.model(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email = self.normalize_email(email)
        )
        user.set_password(password)
        user.save(using=self._db)
        profile = Profile.create_profile(self, user=user, data=validate_data)  # type: ignore
        profile.save()
        
        return user
    
    def create_superuser(self, username=None, email=None, password=None, **extra_fields):
        superuser = self.model(
            username=username,
            email = self.normalize_email(email),
            password = password,
        )
        superuser.set_password(password)
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True
        
        superuser.save(using=self._db)
        profile = Profile.create_profile(self, user=superuser, data={})  # type: ignore
        profile.save()
        return superuser
    
class User(AbstractBaseUser, PermissionsMixin):
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=_(
            "Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."
        ),
        validators=[username_validator],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = models.EmailField(unique=True)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    
    
class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    nickname = models.CharField(max_length=20, null=True, blank=True)
    realname = models.CharField(max_length=128, null=True, blank=True)
    prfile_pic = models.ImageField(null=True, blank=True)
    provier = models.CharField(max_length=128, null=True, blank=True)
    
    def __str__(self):
        return self.user.username
    
    def create_profile(self, user, data):
        first_name = data.get("first_name", "")
        last_name = data.get("last_name", "")
        name = data.get("name", "")
        nickname = data.get("nickname", "")
        
        realname = ""
        if name:
            realname = name
        else:
            realname = first_name + last_name
            
        if not nickname:
            nickname = realname
        
        profile = Profile(
            user=user,
            realname = realname,
            nickname = nickname
        )
        profile.save()
        return profile
    
class Category(models.Model):
    title = models.CharField(max_length=128, unique=True, null=True, blank=False)
    
    def __str__(self):
        return self.title
    
class Post(models.Model):
    title = models.CharField(max_length=10)
    context = models.TextField(max_length=1000)
    price = models.IntegerField()
    post_pic = models.ImageField(null=True, blank=True)
    dt_created = models.DateField(auto_now_add=True)
    dt_update = models.DateField(auto_now=True)
    
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="post")
    category = models.ForeignKey(Category, null=True, on_delete=models.CASCADE)

    def __str__(self):
        return self.title[:10]

class Comment(models.Model):
    content = models.TextField(max_length=500, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="comments")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    
    def __str__(self):
        return self.content[:10]
    
class Reply(models.Model):
    content = models.TextField(max_length=500, blank=False)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, related_name='replies')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Post, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    cancle = models.BooleanField(default=False)


# class Order(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     product = models.ForeignKey(Post, on_delete=models.CASCADE)
#     quantity = models.IntegerField(default=1)
#     order_date = models.DateTimeField(auto_now=True)