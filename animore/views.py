from rest_framework import status, permissions, viewsets, generics
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework.views    import APIView
from django.contrib.auth import get_user_model, authenticate
from .models import UserProfile, Review
from .serializers import (
    UserSerializer, UserLoginSerializer, EmailFindSerializer,
    PwEmailSerializer, PwChangeSerializer, UserProfileSerializer,
    ReviewSerializer, ReviewCreateUpdateSerializer
)
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated, IsAuthenticatedOrReadOnly
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, force_bytes
from django.conf import settings 
from django.core.mail import EmailMessage, send_mail
from django.template.loader import render_to_string
from django.shortcuts import render
from django.urls import reverse


import jwt
import traceback


User = get_user_model()

class SignupView(CreateAPIView):
    model = get_user_model()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def send_activation_email(self, user, request):
        # uid와 token 생성
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = jwt.encode({'user_id': user.pk}, settings.SECRET_KEY, algorithm='HS256')
        print("Generated JWT token:", token)
        # domain 가져오기
        domain = request.get_host() 
        # 계정 활성화 링크 생성
        activation_link = f"http://{domain}{reverse('activate', kwargs={'uid': uid, 'token': token})}"

        # 이메일 템플릿 렌더링
        message = render_to_string('animore/user_activate_email.html', {
            'user': user,
            'activation_link': activation_link,
        })
        
        # 이메일 발송
        send_mail(
            'Activate your account',
            message,
            'tmxjel0823@gmail.com',  # 발신자 이메일 주소
            [user.email],        # 수신자 이메일 주소
            fail_silently=False,
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # 여기서 이메일 전송 로직을 추가할 수 있습니다.
        self.send_activation_email(user, request)

        # 성공적으로 가입한 후, 템플릿을 렌더링하여 보여줍니다.
        return render(request, 'animore/user_activate_email.html', {'user': user})

@api_view(['POST'])
@permission_classes([AllowAny])
def Login(request):
    if request.method == 'POST':
        serializer = UserLoginSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)

        # 'None' 문자열이 반환되는 경우에 대한 처리
        if serializer.validated_data['email'] == "None":
            return Response({"message": 'ID 또는 비밀번호가 틀렸습니다.'}, status=status.HTTP_401_UNAUTHORIZED)
            
        response = {
            'success': True,
            'token': serializer.data['token']
        }
        return Response(response, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAdminUser])
def user_detail(request, pk):
    try:
        user = User.objects.get(pk=pk)
        return Response(UserSerializer(user).data)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response(UserSerializer(request.user).data)

    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class UserActivateView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, uid, token):
        try:
            real_uid = force_str(urlsafe_base64_decode(uid))
            print(real_uid)
            user = User.objects.get(pk=real_uid)
            if user is not None:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('user_id')
                print(type(user))
                print(type(user_id))
                if int(real_uid) == int(user_id):
                    user.is_active = True
                    user.save()
                    return Response(user.email + '계정이 활성화 되었습니다', status=status.HTTP_200_OK)
                return Response('인증에 실패하였습니다', status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response('인증에 실패하였습니다', status=status.HTTP_400_BAD_REQUEST)

        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
            print(traceback.format_exc())
            return Response('인증에 실패하였습니다',status=status.HTTP_400_BAD_REQUEST) 
        
@api_view(["PUT"])
@permission_classes([AllowAny])
def findemail(request):
    serializer = EmailFindSerializer(data=request.data)
    if serializer.is_valid():
        if User.objects.filter(email=serializer.data['email']).exists():
            return Response('존재하는 이메일입니다')
        else:
            return Response('존재하지 않는 이메일입니다')
    return Response('이메일을 다시 입력하세요')

#비밀번호 재설정 이메일 보내기
class PwResetEmailSendView(APIView):
    permission_classes = [AllowAny]
    
    def put(self,request):
        serializer = PwEmailSerializer(data=request.data)
        try:
            if serializer.is_valid():
                user_email = serializer.data['email']
                print(user_email)
                user = User.objects.get(email = user_email)
                print(user)

                # JWT 토큰 생성
                jwt_token = jwt.encode({'user_id': user.pk}, settings.SECRET_KEY, algorithm='HS256')

                message = render_to_string('users/password_reset.html', {
                    'user': user,
                    'domain': 'localhost:8000',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': jwt_token,
                })
                print(message)
                mail_subject = '[SDP] 비밀번호 변경 메일입니다'
                to_email = user.email
                email = EmailMessage(mail_subject, message, to = [to_email])
                email.send()    
                return Response( user.email+ '이메일 전송이 완료되었습니다',status=status.HTTP_200_OK)
            print(serializer.errors)
            return Response('일치하는 유저가 없습니다',status=status.HTTP_400_BAD_REQUEST)
        except( ValueError, OverflowError, User.DoesNotExist):
            user = None
            print(traceback.format_exc())
            return Response('일치하는 유저가 없습니다',status=status.HTTP_400_BAD_REQUEST)

#비밀번호 재설정

class PasswordChangeView(APIView):
    
    model = User
    permission_classes = [AllowAny]

    def put(self, request, uid, token):
        serializer = PwChangeSerializer(data=request.data)
        if serializer.is_valid():
            real_uid = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=real_uid)
            if user is not None:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('user_id')
                if int(real_uid) == int(user_id):
                    print("비밀번호")
                    print(user.password)
                    print(serializer.data['password'])
                    if serializer.data['password']:
                        user2 = authenticate(email=user.email, password=serializer.data['password'])
                        if user2 != None :
                            return Response('기존 비밀번호와 일치합니다',status=status.HTTP_400_BAD_REQUEST)
                        user.set_password(serializer.data.get("password"))
                        print(user.password)
                        user.save()
                        response = {
                            'status': 'success',
                            'code': status.HTTP_200_OK,
                            'message': 'Password updated successfully',
                            'data': []
                        }
                        return Response(response)
                    return Response('비밀번호를 다시 입력해주세요',status=status.HTTP_400_BAD_REQUEST)
                return Response('인증에 실패하였습니다',status=status.HTTP_400_BAD_REQUEST)
            return Response('일치하는 유저가 없습니다',status=status.HTTP_400_BAD_REQUEST)           
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileViewSet(viewsets.ModelViewSet):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # 현재 로그인된 사용자에 해당하는 프로필만 반환
        return UserProfile.objects.filter(user=self.request.user)

class UserProfileSetupView(APIView): #회원가입 후 프로필 설정
    def post(self, request):
        user = request.user  # 로그인한 사용자의 정보 가져오기
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)
        
        profile_serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if profile_serializer.is_valid():
            profile_serializer.save()
            return Response(profile_serializer.data, status=status.HTTP_200_OK)
        return Response(profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserProfileUpdateView(APIView): #프로필 수정
    def patch(self, request):
        user = request.user  # 로그인한 사용자의 정보 가져오기
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

        profile_serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if profile_serializer.is_valid():
            profile_serializer.save()
            return Response(profile_serializer.data, status=status.HTTP_200_OK)
        return Response(profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ReviewListCreateView(generics.ListCreateAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        # 요청한 유저 정보에서 author, username, profile_image를 설정
        serializer.save(
            author=self.request.user,
            username=self.request.user.nickname,  # 사용자 모델의 필드에서 가져옴
            profile_image=self.request.user.profile_image  # 사용자 프로필 사진
        )

class ReviewDetailUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all()
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return ReviewCreateUpdateSerializer
        return ReviewSerializer

    def perform_update(self, serializer):
        serializer.save()