# serializers.py

from rest_framework import serializers
from .models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'password')

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
        )
        return user




from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import AccessToken

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # Add user data to the token
        data['user'] = {
            'id': self.user.id,
            'email': self.user.email,
        }

        # Blacklist old token if it exists
        if self.user.current_token:
            try:
                token = AccessToken(self.user.current_token)
                token.blacklist()
            except Exception as e:
                pass

        # Save the new token
        self.user.current_token = data['access']
        self.user.save()

        return data