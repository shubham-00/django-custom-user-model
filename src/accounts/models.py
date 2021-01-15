from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.core.validators import RegexValidator
from django.contrib.auth.models import PermissionsMixin


USERNAME_REGEX = "^[A-Za-z0-9.+-]*$"


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError("Email Address is required!")

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.create_user(username, email, password=password)
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(
        max_length=500,
        validators=[
            RegexValidator(
                regex=USERNAME_REGEX,
                message="Username must be alphanumeric",
                code="invalid_username",
            )
        ],
        unique=True,
    )
    email = models.EmailField(max_length=255, unique=True, verbose_name="Email Address")
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]
