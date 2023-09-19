from utils.shortcuts import get_env

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'Selab_oj',  # 数据库名字
        'USER': 'postgres',
        'PASSWORD': '123456',
        'HOST': '127.0.0.1',
        'PORT': '5432',
    }
}

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
    "host": get_env("REDIS_HOST", "oj-redis"),
    "port": get_env("REDIS_PORT", "6379")
}

DEBUG = False

ALLOWED_HOSTS = ['*']

DATA_DIR = "/data"
