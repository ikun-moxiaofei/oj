from django.contrib.auth.models import AbstractBaseUser
from django.conf import settings
from django.db import models
from utils.models import JSONField


class AdminType(object):
    REGULAR_USER = "Regular User"
    ADMIN = "Admin"
    SUPER_ADMIN = "Super Admin"


class ProblemPermission(object):
    NONE = "None"
    OWN = "Own"
    ALL = "All"


class UserManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, username):
        return self.get(**{f"{self.model.USERNAME_FIELD}__iexact": username})


class User(AbstractBaseUser):
    username = models.TextField(unique=True)
    email = models.TextField(null=True)
    create_time = models.DateTimeField(auto_now_add=True, null=True)
    # 用户类型
    admin_type = models.TextField(default=AdminType.REGULAR_USER)
    # 问题权限
    problem_permission = models.TextField(default=ProblemPermission.NONE)
    # 重置密码的令牌。
    reset_password_token = models.TextField(null=True)
    # 重置密码令牌的过期时间
    reset_password_token_expire_time = models.DateTimeField(null=True)
    # 单点登录（SSO）的令牌
    auth_token = models.TextField(null=True)
    two_factor_auth = models.BooleanField(default=False)
    tfa_token = models.TextField(null=True)
    session_keys = JSONField(default=list)
    # open api key
    open_api = models.BooleanField(default=False)
    open_api_appkey = models.TextField(null=True)
    is_disabled = models.BooleanField(default=False)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def is_admin(self):
        return self.admin_type == AdminType.ADMIN

    def is_super_admin(self):
        return self.admin_type == AdminType.SUPER_ADMIN

    def is_admin_role(self):
        return self.admin_type in [AdminType.ADMIN, AdminType.SUPER_ADMIN]

    def can_mgmt_all_problem(self):
        return self.problem_permission == ProblemPermission.ALL

    def is_contest_admin(self, contest):
        return self.is_authenticated and (contest.created_by == self or self.admin_type == AdminType.SUPER_ADMIN)

    class Meta:
        db_table = "user"


class UserProfile(models.Model):
    # user: 与 User 模型关联的一对一字段
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    acm_problems_status = JSONField(default=dict)
    # 存储 OI 题目的解题状态
    oi_problems_status = JSONField(default=dict)

    real_name = models.TextField(null=True)
    avatar = models.TextField(default=f"{settings.AVATAR_URI_PREFIX}/default.png")
    blog = models.URLField(null=True)
    mood = models.TextField(null=True)
    github = models.TextField(null=True)
    school = models.TextField(null=True)
    major = models.TextField(null=True)
    language = models.TextField(null=True)
    # ACM 题目的通过数量。
    accepted_number = models.IntegerField(default=0)
    # OI 题目的总分
    total_score = models.BigIntegerField(default=0)
    submission_number = models.IntegerField(default=0)

    def add_accepted_problem_number(self):
        self.accepted_number = models.F("accepted_number") + 1
        self.save()

    # 增加总提交次数
    def add_submission_number(self):
        self.submission_number = models.F("submission_number") + 1
        self.save()

    # 计算总分时， 应先减掉上次该题所得分数， 然后再加上本次所得分数
    def add_score(self, this_time_score, last_time_score=None):
        last_time_score = last_time_score or 0
        self.total_score = models.F("total_score") - last_time_score + this_time_score
        self.save()

    class Meta:
        db_table = "user_profile"
