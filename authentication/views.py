from dj_rest_auth import views as dj_rest_auth_views
from dj_rest_auth.serializers import JWTSerializer, LoginSerializer
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import generics
from rest_framework.permissions import AllowAny

from .serializers import SignupSerializer


class LoginView(dj_rest_auth_views.LoginView):
    """
    ログイン
    """

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: JWTSerializer,
            400: OpenApiResponse(description="Unable to log in with provided credentials."),
        },
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class SignupView(generics.CreateAPIView):
    """
    ユーザー登録
    """

    serializer_class = SignupSerializer
    permission_classes = [AllowAny]
