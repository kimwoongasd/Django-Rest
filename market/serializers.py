from rest_framework import serializers
from dj_rest_auth.registration.serializers import RegisterSerializer
from django.contrib.auth import get_user_model
from .models import User, Post, Profile, Comment, Reply, Category, Cart


User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'realname',
            'nickname',
            'prfile_pic',
            'provier',
        ]

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'profile',
        ]
        
    def create(self, validated_data):
        user = User.objects.create_user(  # type: ignore
            validated_data
        )
        
        return user

class CustomRegisterSerializer(RegisterSerializer):
    
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data['first_name'] = self.validated_data.get('first_name', '') # type: ignore
        data['last_name'] = self.validated_data.get('lsat_name', '') # type: ignore

        return data
        
class ReplySerializer(serializers.ModelSerializer):
    class Meta:
        model = Reply
        fields = '__all__'

class CommentSerializer(serializers.ModelSerializer):
    replies = ReplySerializer(many=True, read_only=True)
    class Meta:
        model = Comment
        fields = '__all__'

class  CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'
        
class PostSerializer(serializers.ModelSerializer):
    comments = CommentSerializer(many=True, read_only=True)
    class Meta:
        model = Post
        fields = ["title", "context", "price", "category", "comments"]
        
class CartSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    product = serializers.PrimaryKeyRelatedField(queryset=Post.objects.all())
    class Meta:
        model = Cart
        fields = '__all__'