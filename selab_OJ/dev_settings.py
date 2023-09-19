# coding=utf-8
import os
from utils.shortcuts import get_env

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'HOST': get_env('POSTGRES_HOST', '127.0.0.1'),
        'PORT': get_env('POSTGRES_PORT', '5432'),
        'NAME': get_env('POSTGRES_DB', 'Selab_oj'),
        'USER': get_env('POSTGRES_USER', 'onlinejudge'),
        'PASSWORD': get_env('POSTGRES_PASSWORD', 'onlinejudge')
    }
}
#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'selab_oj_',  # 数据库名字
#         'USER': 'root',
#         'PASSWORD': '123456',
#         'HOST': '127.0.0.1',  # 那台机器安装了MySQL
#         'PORT': 3306,
#     }
# }


REDIS_CONF = {
    'host': get_env('REDIS_HOST', '127.0.0.1'),
    'port': get_env('REDIS_PORT', '6380')
}


DEBUG = True

ALLOWED_HOSTS = ["*"]

DATA_DIR = f"{BASE_DIR}/data"
