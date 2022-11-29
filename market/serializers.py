from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import User

User = get_user_model()
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        
    def create(self, validated_data):
        user = User.objects.create_user(
            nickname = validated_data['nickname'],
            email = validated_data['email'],
            password = validated_data['password']
        )
        
        return user
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'