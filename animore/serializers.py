from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import validate_email
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.models import update_last_login
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from datetime import datetime, timedelta
import jwt

User = get_user_model()
validate_username = UnicodeUsernameValidator()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = (
            "id",
            #"username",
            "password",
            "gender",
            "nickname",
            "birthdate",
            "email",
            "address",
        )
        read_only_fields = ("id",)

    def validate_email(self, obj):
        try:
            validate_email(obj)
            return obj
        except ValidationError:
            raise serializers.ValidationError('메일 형식이 올바르지 않습니다.')


    def validate_username(self, obj):
        try:
            validate_username(obj)
            return obj
        except ValidationError:
            raise serializers.ValidationError('메일 형식이 올바르지 않습니다.')

    def create(self, validated_data):
        user = super().create(validated_data)
        user.set_password(validated_data["password"])
        user.is_active = False  # 사용자는 처음에는 비활성화 상태
        user.save()

        # JWT 토큰 생성
        payload = {
            'user_id': user.pk,
            'email': user.email,
            'exp': datetime.utcnow() + timedelta(hours=24)  # 유효 시간 설정 (24시간)
        }
        jwt_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        # 이메일 전송을 위한 메시지 작성
        message = render_to_string('animore/user_activate_email.html', {
            'user': user,
            'domain': 'localhost:8000',  # 실제 배포 환경에서는 도메인을 변경해야 함
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': jwt_token,  # JWT 토큰을 포함
        })

        mail_subject = '[SDP] 회원가입 인증 메일입니다'
        to_email = user.email
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.send()

        return user
    


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=64)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)
        user = authenticate(email=email, password=password)
        
        if user is None:
            return {
                'email': 'None'
            }

        refresh = RefreshToken.for_user(user)
        update_last_login(None, user)

        return {
            'email': user.email,
            'token': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }
    
class EmailFindSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=64,required=True)

#비밀번호 이메일 보낼 때 쓰는 거
class PwEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=64)

    def validate_email(self, value):
        '''데이터베이스에 존재하는지 확인'''
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("존재하지 않는 이메일입니다.")
        else:
            return value

#비밀번호 변경할 때 쓰는거
class PwChangeSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)