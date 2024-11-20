from django.contrib.auth.models import AbstractUser, AbstractBaseUser, BaseUserManager
from django.db import models
from django.conf import settings
from django.contrib.auth.models import UserManager, PermissionsMixin

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError(('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    """custom user model"""
    username = None
    GENDER_MALE = "male"
    GENDER_FEMALE = "female"
    GENDER_OTHER = "other"
    GENDER_CHOICES = (
        (GENDER_MALE, "Male"),
        (GENDER_FEMALE, "Female"),
        (GENDER_OTHER, "Other"),
    )
    gender = models.CharField(choices=GENDER_CHOICES, max_length=10, blank=True)
    nickname = models.CharField(max_length=20, blank=True)
    birthdate = models.DateField(blank=True, null=True)
    email = models.EmailField(max_length=64,unique=True)
    address = models.CharField(max_length=100, blank=True)

    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

    def __str__(self):
        return self.email

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    introduce = models.TextField(blank=True)

    def __str__(self):
        return f'{self.user.email} Profile'

class Review(models.Model):
    profile = models.ImageField(upload_to='profile_images/', blank=True, null=True)  # 프로필 사진
    name = models.CharField(max_length=100)  # 사용자 이름
    title = models.CharField(max_length=100)  # 제목
    content = models.TextField()  # 내용
    image = models.ImageField(upload_to='post_images/', blank=True, null=True)  # 게시글 사진
    dt_created = models.DateTimeField(auto_now_add=True)  # 생성 시간
    dt_updated = models.DateTimeField(auto_now=True)  # 수정 시간

    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.title} - {self.username}"