from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class LoginTokenObtainSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super(LoginTokenObtainSerializer, self).validate(attrs)
        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        update_last_login(None, self.user)

        return data


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)

    def create(self, validated_data):
        password = validated_data.pop("password")
        auth_user = get_user_model().objects.create_user(
            username=validated_data["username"],
            email=validated_data["username"],
            password=password,
            is_active=True,
        )
        return auth_user
