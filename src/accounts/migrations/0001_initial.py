# Generated by Django 3.1.5 on 2021-01-14 07:51

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('username', models.CharField(max_length=500, unique=True, validators=[django.core.validators.RegexValidator(code='invalid_username', message='Username must be alphanumeric', regex='^[A-Za-z0-9.+-]*$')])),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='Email Address')),
                ('is_admin', models.BooleanField(default=False)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
