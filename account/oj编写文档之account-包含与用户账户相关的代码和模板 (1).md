- models文件：
   - User模型和UserProfile模型（用户额外信息)<br />`class User(AbstractBaseUser):<br /> class UserProfile(models.Model):`
      - AbstractBaseUser是一个用于定义自定义用户模型的抽象基类。当你希望使用自定义的字段和方法来扩展用户模型时，可以继承自 AbstractBaseUser
      - 使用 AbstractBaseUser需要一些额外的工作，因为你需要自己处理一些与用户认证相关的功能。例如，你需要自定义用户管理器，并为用户模型提供一些必需的方法（如 is_authenticated、get_full_name）。这为你提供了更大的定制能力，但也需要更多的手动配置。
      - 如果你需要一个高度定制的用户模型，或者需要集成其他身份验证系统，那么使用 AbstractBaseUser
   - UserManager为自定义的 Django 管理器（Manager），在 Django 中，管理器允许你封装一些与数据库交互的常见操作，以及提供额外的查询方法。在这里，UserManager 是针对 User 模型的一个自定义管理器。**在 Django 的默认情况下，如果你使用 AbstractBaseUser 创建自定义用户模型，那么需要为该模型定义一个管理器**。UserManager 继承自 models.Manager，并且通过设置 objects = UserManager() 将这个自定义管理器关联到了 User 模型。
```python
class UserManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, username):
        return self.get(**{f"{self.model.USERNAME_FIELD}__iexact": username})
```

   - 这个管理器的主要特征是定义了一个方法 get_by_natural_key(self, username)，这个方法用于通过用户名获取用户对象。这在 Django 的身份验证系统中是很有用的，因为身份验证系统可能需要通过用户提供的凭据（例如用户名）来查找用户。
```python
use_in_migrations = True: 这个属性告诉 Django 在数据库迁移过程中也使用这个管理器。

get_by_natural_key(self, username): 这是一个自定义的方法。

f"{self.model.USERNAME_FIELD}__iexact": 这是一个格式化字符串，其中使用 f-string 将 self.model.USERNAME_FIELD 的值插入到字符串中。这构建了一个查询条，__iexact 是 Django ORM 中的查询操作符，用于执行不区分大小写的精确匹配。
{f"{self.model.USERNAME_FIELD}__iexact": username}: 这是一个字典，其中的键是查询条件，值是要匹配的用户名。这里的查询条件即是根据不区分大小写的精确匹配查找用户的用户名。self.get 是 Django 模型管理器中的方法

该代码的目的是在数据库中通过不区分大小写的精确匹配查找具有特定用户名的用户对象，并将其返回
```

   - 通过将 UserManager 关联到 User 模型，可以使用这个管理器来执行与用户相关的数据库查询操作，而不仅仅局限于默认提供的 objects 管理器。这样可以在模型层面更灵活地组织和执行数据库操作
- views文件：
   - oj.py
      - **_用户登录_**(user_login_api)
```python
class UserLoginAPI(APIView):
    @validate_serializer(UserLoginSerializer)
    def post(self, request):
        data = request.data
        user = auth.authenticate(username=data["username"], password=data["password"])
        # 如果用户名或密码错误，则返回无
        if user:
            if user.is_disabled:
                return self.error("Your account has been disabled")
            if not user.two_factor_auth:
                auth.login(request, user)
                return self.success("Succeeded")
        else:
            return self.error("Invalid username or password")
```

         - @validate_serializer(UserLoginSerializer) 是一个装饰器，用于验证请求数据是否符合 UserLoginSerializer 的定义。这是一个自定义的序列化器，用于验证和处理用户登录请求中的数据
```python
def validate_serializer(serializer):
    def validate(view_method):
        @functools.wraps(view_method)
        def handle(*args, **kwargs):
            self = args[0]
            request = args[1]
            s = serializer(data=request.data)
            if s.is_valid():
                request.data = s.data
                request.serializer = s
                return view_method(*args, **kwargs)
            else:
                return self.invalid_serializer(s)

        return handle

    return validate

```

         -  用途：在执行 API 视图方法之前，对请求的数据进行序列化器验证。
         - validate 函数接受一个视图方法 view_method 作为参数，然后返回一个新的函数 handle。在这个函数内部，首先从参数中获取 self 和 request，然后使用装饰器接收的序列化器类 serializer 创建一个序列化器实例 s。接下来，通过调用 s.is_valid() 检查请求数据是否符合序列化器的规则。如果数据有效，将序列化器的数据和实例存储在请求对象中，然后调用原始的视图方法 view_method(*args, **kwargs)。如果序列化器验证失败，调用 self.invalid_serializer(s)，这个地方可能是处理无效序列化器的逻辑，比如返回一个错误响应。
         - `@functools.wraps(view_method)`<br />这个装饰器可以**保留被装饰的函数的原始信息**，可以避免被装饰的函数的元数据（传入的函数参数）丢失或者覆盖，该装饰器代码如下
```python
WRAPPER_ASSIGNMENTS = ('__module__', '__name__', '__qualname__', '__doc__',
                       '__annotations__')
WRAPPER_UPDATES = ('__dict__',)
def update_wrapper(wrapper,
                   wrapped,
                   assigned = WRAPPER_ASSIGNMENTS,
                   updated = WRAPPER_UPDATES):
   for attr in assigned:
        try:
            value = getattr(wrapped, attr)
        except AttributeError:
            pass
        else:
            setattr(wrapper, attr, value)
    for attr in updated:
        getattr(wrapper, attr).update(getattr(wrapped, attr, {}))
    wrapper.__wrapped__ = wrapped
    return wrapper

def wraps(wrapped,
          assigned = WRAPPER_ASSIGNMENTS,
          updated = WRAPPER_UPDATES):
   return partial(update_wrapper, wrapped=wrapped,
                   assigned=assigned, updated=updated)
```

         - `user = auth.authenticate(username=data["username"], password=data["password"])`<br />这是 Django 的身份验证模块的函数，用于验证用户的身份。它接受用户名和密码作为参数，**并返回与之匹配的用户对象**。如果用户名或密码错误，返回 None。在 Django 项目中，配置身份验证系统通常是在项目的设置文件（settings.py）中进行的， 如果使用了自定义的用户模型，需要在设置中指定它。<br />`AUTH_USER_MODEL = 'yourapp.YourUserModel'`<br />同时，使用时需要导入<br />`from django.contrib.auth import authenticate`
         - `auth.login(request, user)`<br />是 Django 身份验证系统中自带的用于登录用户的函数。它将用户对象关联到当前的请求和会话中，表示用户已经通过身份验证并且已登录，login(request, user) 被调用，将用户与当前请求关联起来，表示用户已经登录。这样，就可以在后续的请求中**通过 request.user 来获取当前登录的用户**
      - **_退出登录_**（user_logout_api）
```python
class UserLogoutAPI(APIView):
    def get(self, request):
        auth.logout(request)
        return self.success()
```

         - logout和上面的login差不多
      - **_用户注册_**（user_register_api）
```python
class UserRegisterAPI(APIView):
    @validate_serializer(UserRegisterSerializer)
    def post(self, request):
        if not SysOptions.allow_register:
            return self.error("Register function has been disabled by admin")

        data = request.data
        data["username"] = data["username"].lower()
        data["email"] = data["email"].lower()
        captcha = Captcha(request)
        if not captcha.check(data["captcha"]):
            return self.error("Invalid captcha")
        if User.objects.filter(username=data["username"]).exists():
            return self.error("Username already exists")
        if User.objects.filter(email=data["email"]).exists():
            return self.error("Email already exists")
        user = User.objects.create(username=data["username"], email=data["email"])
        user.set_password(data["password"])
        user.save()
        UserProfile.objects.create(user=user)
        return self.success("Succeeded")
```

         - ` @validate_serializer(UserRegisterSerializer)`<br />装饰器和上面的是一样的
         - `SysOptions.allow_register`<br />是一个自定义属性，用于控制是否开启用户注册功能
         - 用lower()把用户名和邮箱改为小写
         - 使用自定义Captcha工具检验验证码是否正确
```python
class Captcha(object):
    def __init__(self, request):
        """
        初始化,设置各种属性
        """
        self.django_request = request
        self.session_key = "_django_captcha_key"
        self.captcha_expires_time = "_django_captcha_expires_time"

        # 验证码图片尺寸
        self.img_width = 90
        self.img_height = 30
    def check(self, code):
        # 从会话中获取之前保存的验证码，如果没有保存过验证码，则设置默认值为空字符串。
        _code = self.django_request.session.get(self.session_key) or ""
        if not _code:
            return False
        # 从会话中获取之前保存的验证码过期时间，如果没有保存过过期时间，则设置默认值为 0。
        expires_time = self.django_request.session.get(self.captcha_expires_time) or 0
        # 从 Django 会话中删除之前保存的验证码及其过期时间信息
        del self.django_request.session[self.session_key]
        del self.django_request.session[self.captcha_expires_time]
        # 检查用户输入的验证码是否与之前保存的验证码一致（忽略大小写），并且当前时间在验证码过期时间之前。
        if _code.lower() == str(code).lower() and time.time() < expires_time:
            return True
        else:
            return False
```

         - 判断用户名和邮箱是否在数据库中以及存在，一切通过则存入User模型和UserProfile模型
      - **_修改密码_**（user_change_password_api）
```python
class UserChangePasswordAPI(APIView):
    @validate_serializer(UserChangePasswordSerializer)
    @login_required
    def post(self, request):
        data = request.data
        username = request.user.username
        user = auth.authenticate(username=username, password=data["old_password"])
        if user:
            if user.two_factor_auth:
                if "tfa_code" not in data:
                    return self.error("tfa_required")
                if not OtpAuth(user.tfa_token).valid_totp(data["tfa_code"]):
                    return self.error("Invalid two factor verification code")
            user.set_password(data["new_password"])
            user.save()
            return self.success("Succeeded")
        else:
            return self.error("Invalid old password")
```

         - `@validate_serializer(UserChangePasswordSerializer)`<br />和上面同理
         - `@login_required`<br />检查用户是否已经登录
```python
class login_required(BasePermissionDecorator):
    def check_permission(self):
        return self.request.user.is_authenticated
```

         - `auth.authenticate(username=username, password=data["old_password"])`**Django自带的验证用户的旧密码是否正确，如果正确，会返回用户对象，否则会返回None。
         - `user.set_password(data["new_password"])`<br />set_password 方法是 Django 框架自带的方法，属于 django.contrib.auth.models.User 模型的一部分。这个方法的目的是安全地设置用户的密码，并确保密码存储在数据库中时是经过哈希处理的
      - **_修改邮箱_**（user_change_email_api）
```python
class UserChangeEmailAPI(APIView):
    @validate_serializer(UserChangeEmailSerializer)
    @login_required
    def post(self, request):
        data = request.data
        user = auth.authenticate(username=request.user.username, password=data["password"])
        if user:
            if user.two_factor_auth:
                if "tfa_code" not in data:
                    return self.error("tfa_required")
                if not OtpAuth(user.tfa_token).valid_totp(data["tfa_code"]):
                    return self.error("Invalid two factor verification code")
            data["new_email"] = data["new_email"].lower()
            if User.objects.filter(email=data["new_email"]).exists():
                return self.error("The email is owned by other account")
            user.email = data["new_email"]
            user.save()
            return self.success("Succeeded")
        else:
            return self.error("Wrong password")
```

         - 基本相同
      - **_重置密码_**（apply_reset_password_api和ResetPasswordAPI）
```python
class ApplyResetPasswordAPI(APIView):
    @validate_serializer(ApplyResetPasswordSerializer)
    def post(self, request):
        # 如果用户已经登录，返回错误消息
        if request.user.is_authenticated:
            return self.error("You have already logged in, are you kidding me? ")
        
        # 从请求中获取数据
        data = request.data
        
        # 验证验证码
        captcha = Captcha(request)
        if not captcha.check(data["captcha"]):
            return self.error("Invalid captcha")
        
        try:
            # 根据提供的邮箱查找用户
            user = User.objects.get(email__iexact=data["email"])
        except User.DoesNotExist:
            # 如果用户不存在，返回错误消息
            return self.error("User does not exist")
        
        # 检查重置密码令牌是否存在并在有效期内
        if user.reset_password_token_expire_time and 0 < int(
                (user.reset_password_token_expire_time - now()).total_seconds()) < 20 * 60:
            return self.error("You can only reset password once per 20 minutes")
        
        # 生成新的重置密码令牌和设置有效期为20分钟
        user.reset_password_token = rand_str()
        user.reset_password_token_expire_time = now() + timedelta(minutes=20)
        user.save()
        
        # 准备渲染邮件模板的数据
        render_data = {
            "username": user.username,
            "website_name": SysOptions.website_name,
            "link": f"{SysOptions.website_base_url}/reset-password/{user.reset_password_token}"
        }
        
        # 渲染邮件 HTML 内容
        email_html = render_to_string("reset_password_email.html", render_data)
        
        # 异步发送重置密码邮件
        send_email_async.send(from_name=SysOptions.website_name_shortcut,
                              to_email=user.email,
                              to_name=user.username,
                              subject="Reset your password",
                              content=email_html)
        
        # 返回成功消息
        return self.success("Succeeded")

```
```python
class ResetPasswordAPI(APIView):
    @validate_serializer(ResetPasswordSerializer)
    def post(self, request):
        # 从请求中获取数据
        data = request.data
        
        # 验证验证码
        captcha = Captcha(request)
        if not captcha.check(data["captcha"]):
            return self.error("Invalid captcha")
        
        try:
            # 根据提供的重置密码令牌查找用户
            user = User.objects.get(reset_password_token=data["token"])
        except User.DoesNotExist:
            # 如果令牌对应的用户不存在，返回错误消息
            return self.error("Token does not exist")
        
        # 检查重置密码令牌是否过期
        if user.reset_password_token_expire_time < now():
            return self.error("Token has expired")
        
        # 清除重置密码令牌，关闭两步验证，设置新密码并保存用户对象
        user.reset_password_token = None
        user.two_factor_auth = False
        user.set_password(data["password"])
        user.save()
        
        # 返回成功消息
        return self.success("Succeeded")

```

         - ApplyResetPasswordAPI 处理用户发起的申请密码重置的请求，生成新的重置密码令牌，并发送包含重置密码链接的邮件。ResetPasswordAPI 处理实际的密码重置操作，验证用户提供的重置密码令牌，清除令牌，关闭两步验证，设置新密码。

      - _**显示验证码**_（show_captcha）
```python
class CaptchaAPIView(APIView):
    def get(self, request):
        return self.success(img2base64(Captcha(request).get()))
```

         - `Captcha(request).get()`<br />建一个 Captcha 对象，Captcha 是用于生成验证码图片的类，它接受一个 Django 请求对象作为参数。通过调用 get() 方法生成验证码图片
         - `img2base64(...)`<br />将生成的验证码图片转换为 base64 编码。这个过程可能是一个自定义函数，名为 img2base64
         - `return self.success(...)`<br />返回一个包含 base64 编码的验证码图片数据的成功响应。
      - _**检查用户名或电子邮件是否以及存在**_（check_username_or_email）
```python
class UsernameOrEmailCheck(APIView):
    @validate_serializer(UsernameOrEmailCheckSerializer)
    def post(self, request):
        """
        check username or email is duplicate
        """
        # 从请求中获取数据
        data = request.data
        
        # 初始化结果字典，True 表示已经存在
        result = {
            "username": False,
            "email": False
        }
        
        # 如果请求中提供了用户名
        if data.get("username"):
            # 检查数据库中是否已存在相同的用户名（不区分大小写）
            result["username"] = User.objects.filter(username=data["username"].lower()).exists()
        
        # 如果请求中提供了电子邮件
        if data.get("email"):
            # 检查数据库中是否已存在相同的电子邮件（不区分大小写）
            result["email"] = User.objects.filter(email=data["email"].lower()).exists()
        
        # 返回包含检查结果的成功响应
        return self.success(result)

```

      - **_用户个人资料_**（user_profile_api）
```python
class UserProfileAPI(APIView):
    @method_decorator(ensure_csrf_cookie)
    # 用于返回用户的个人信息
    def get(self, request, **kwargs):
        """
        判断是否登录， 若登录返回用户信息
        """
        # 获取请求对象中的user属性，判断用户是否已经登录。如果没有登录，就返回一个空的成功信息。
        user = request.user
        if not user.is_authenticated:
            return self.success()

        # 定义一个show_real_name变量，用于控制是否返回用户的真实姓名。默认为False，表示不返回。
        show_real_name = False
        username = request.GET.get("username")
        try:
            if username:
                user = User.objects.get(username=username, is_disabled=False)
            else:
                user = request.user
                # api返回的是自己的信息，可以返real_name
                show_real_name = True
        except User.DoesNotExist:
            return self.error("User does not exist")
        return self.success(UserProfileSerializer(user.userprofile, show_real_name=show_real_name).data)

    @validate_serializer(EditUserProfileSerializer)
    @login_required
    def put(self, request):
        data = request.data
        # 获取请求的数据，并将其赋值给user_profile变量，这是一个UserProfile对象，表示用户的个人信息。
        user_profile = request.user.userprofile
        # 更新用户个人资料对象的属性
        for k, v in data.items():
            setattr(user_profile, k, v)
        user_profile.save()
        return self.success(UserProfileSerializer(user_profile, show_real_name=True).data)
```

         - @method_decorator(ensure_csrf_cookie)
            - method_decorator和ensure_csrf_cookie都是自带的，前者可以把函数装饰器用于类的方法上，后者用于确保在响应中包含 CSRF（Cross-Site Request Forgery）令牌的 cookie。这个令牌用于防范跨站请求伪造攻击
         - `setattr(user_profile, k, v)`<br />setattr 是 Python 内置函数，用于设置对象的属性值。在这里，setattr(user_profile, k, v) 的作用是将 user_profile 对象的属性 k 的值设置为 v。
      - **_显示ID刷新_**（display_id_fresh）
```python
class ProfileProblemDisplayIDRefreshAPI(APIView):
    @login_required
    def get(self, request):
        # 获取当前用户的用户配置信息（UserProfile）
        profile = request.user.userprofile
        # 从用户配置信息中获取 ACM 和 OI 问题的状态信息
        acm_problems = profile.acm_problems_status.get("problems", {})
        oi_problems = profile.oi_problems_status.get("problems", {})
        # 从状态信息中提取问题的 ID 列表，合并 ACM 和 OI 两类问题的 ID
        ids = list(acm_problems.keys()) + list(oi_problems.keys())
        # 如果 ID 列表为空，直接返回成功响应
        if not ids:
            return self.success()
        # 查询数据库，获取这些问题的实际显示 ID
        display_ids = Problem.objects.filter(id__in=ids, visible=True).values_list("_id", flat=True)
        # 构建 ID 映射关系，将问题的原始 ID 映射到实际显示 ID
        id_map = dict(zip(ids, display_ids))
        # 更新 ACM 问题的状态信息，添加 "_id" 字段表示实际显示 ID
        for k, v in acm_problems.items():
            v["_id"] = id_map[k]
        # 更新 OI 问题的状态信息，添加 "_id" 字段表示实际显示 ID
        for k, v in oi_problems.items():
            v["_id"] = id_map[k]
        # 保存更新后的用户配置信息，更新的字段包括 ACM 问题状态、OI 问题状态
        profile.save(update_fields=["acm_problems_status", "oi_problems_status"])
        # 返回成功响应
        return self.success()
```

         - `display_ids = Problem.objects.filter(id__in=ids, visible=True).values_list("_id", flat=True)`<br />从 Problem 模型中获取那些 ID 在 ids 列表中且可见的问题的 _id 字段值，存储在 display_ids 列表中。
         - `id_map = dict(zip(ids, display_ids))`<br />将 ids 列表中的元素作为键，display_ids 列表中的元素作为对应的值，创建一个字典。这个字典就是将问题的原始 ID 映射到实际显示 ID 的映射关系。
      - **_头像上传_**（avatar_upload_api）
```python
class AvatarUploadAPI(APIView):
    request_parsers = ()  # 禁用默认的请求解析器，这里没有使用DRF的RequestParser

    @login_required  # 使用@login_required装饰器确保用户已登录才能访问这个API
    def post(self, request):
        # 使用ImageUploadForm验证上传的表单数据
        form = ImageUploadForm(request.POST, request.FILES)
        
        if form.is_valid():  # 如果表单验证通过
            avatar = form.cleaned_data["image"]  # 获取上传的图片数据
        else:
            return self.error("Invalid file content")  # 如果表单验证失败，返回错误响应

        if avatar.size > 2 * 1024 * 1024:  # 如果图片大小超过2MB，返回错误响应
            return self.error("Picture is too large")

        suffix = os.path.splitext(avatar.name)[-1].lower()  # 获取图片文件后缀名
        # 检查文件格式是否支持
        if suffix not in [".gif", ".jpg", ".jpeg", ".bmp", ".png"]:
            return self.error("Unsupported file format")

        name = rand_str(10) + suffix  # 生成一个随机文件名
        # 将上传的图片数据写入到服务器的指定目录中
        with open(os.path.join(settings.AVATAR_UPLOAD_DIR, name), "wb") as img:
            for chunk in avatar:
                img.write(chunk)

        user_profile = request.user.userprofile  # 获取当前用户的用户配置信息

        # 更新用户配置信息中的头像字段，存储头像文件的相对路径
        user_profile.avatar = f"{settings.AVATAR_URI_PREFIX}/{name}"
        user_profile.save()  # 保存更新后的用户配置信息到数据库

        return self.success("Succeeded")  # 返回成功响应

```

      - **_验证tfa_**（**tfa_required_check**）
```python
class CheckTFARequiredAPI(APIView):
    @validate_serializer(UsernameOrEmailCheckSerializer)
    def post(self, request):
        # 获取request的数据，赋值给data变量
        data = request.data
        # 初始化result变量为假
        result = False
        # 如果数据中有username键，说明提供了用户名
        if data.get("username"):
            try:
                # 从User模型中获取对应的用户对象，赋值给user变量
                user = User.objects.get(username=data["username"])
                # 检查用户对象的two_factor_auth属性是否为真，赋值给result变量
                result = user.two_factor_auth
            except User.DoesNotExist:
                # 如果找不到对应的用户对象，就忽略这个异常，保持result变量为假
                pass
        # 返回一个成功的响应，包含result变量的值
        return self.success({"result": result})
```

      - **_2FA两重身份验证_**（two_factor_auth_api）get 方法：获取 Two-Factor Authentication 的 QR Code
```python
class TwoFactorAuthAPI(APIView):
    @login_required  # 使用@login_required装饰器确保用户已登录才能访问这个API
    def get(self, request):
        user = request.user  # 获取当前登录用户
        if user.two_factor_auth:  # 如果用户已经开启了Two-Factor Authentication，返回错误响应
            return self.error("2FA is already turned on")
        
        # 生成一个随机的 Two-Factor Authentication 令牌并保存到用户的配置信息中
        token = rand_str()
        user.tfa_token = token
        user.save()

        # 生成二维码的标签，包含网站名和用户用户名
        label = f"{SysOptions.website_name_shortcut}:{user.username}"
        
        # 使用 OtpAuth 生成 TOTP URI，并生成对应的二维码图片
        image = qrcode.make(OtpAuth(token).to_uri("totp", label, SysOptions.website_name.replace(" ", "")))

        # 将二维码图片转换成 base64 格式并返回
        return self.success(img2base64(image))

    @login_required  # 使用@login_required装饰器确保用户已登录才能访问这个API
    @validate_serializer(TwoFactorAuthCodeSerializer)  # 使用验证器确保请求数据的有效性
    def post(self, request):
        code = request.data["code"]  # 获取用户提交的 Two-Factor Authentication 验证码
        user = request.user  # 获取当前登录用户

        # 验证用户提交的验证码是否有效
        if OtpAuth(user.tfa_token).valid_totp(code):
            user.two_factor_auth = True  # 开启 Two-Factor Authentication
            user.save()
            return self.success("Succeeded")
        else:
            return self.error("Invalid code")  # 验证码无效，返回错误响应

    @login_required  # 使用@login_required装饰器确保用户已登录才能访问这个API
    @validate_serializer(TwoFactorAuthCodeSerializer)  # 使用验证器确保请求数据的有效性
    def put(self, request):
        code = request.data["code"]  # 获取用户提交的 Two-Factor Authentication 验证码
        user = request.user  # 获取当前登录用户
        
        if not user.two_factor_auth:  # 如果用户尚未开启 Two-Factor Authentication，返回错误响应
            return self.error("2FA is already turned off")

        # 验证用户提交的验证码是否有效
        if OtpAuth(user.tfa_token).valid_totp(code):
            user.two_factor_auth = False  # 关闭 Two-Factor Authentication
            user.save()
            return self.success("Succeeded")
        else:
            return self.error("Invalid code")  # 验证码无效，返回错误响应
```

         - get 方法：获取 Two-Factor Authentication 的 QR Code，用户使用该接口获取设置 Two-Factor Authentication 所需的 QR Code 图片。如果用户已经开启了 Two-Factor Authentication，返回错误响应。生成一个随机的 Two-Factor Authentication 令牌，并将其保存到用户的配置信息中。生成包含网站名和用户名的二维码标签。使用 OtpAuth 生成 TOTP URI，并**生成对应的二维码图片。将二维码图片转换成 base64 格式并返回给用户**。
         - post 方法：启用 Two-Factor Authentication用户使用该接口提交 Two-Factor Authentication 的验证码以启用该功能。验证用户提交的验证码是否有效，如果有效，则**将用户的 Two-Factor Authentication 设置为启用**。
         - put 方法：关闭 Two-Factor Authentication用户使用该接口提交 Two-Factor Authentication 的验证码以关闭该功能。如果用户尚未开启 Two-Factor Authentication，返回错误响应。验证用户提交的验证码是否有效，如果有效，则**将用户的 Two-Factor Authentication 设置为关闭**。
      - **_用户排名_**（user_rank_api）
```python
class UserRankAPI(APIView):
    def get(self, request):
        # 从请求参数中获取比赛规则类型，如果不存在或者不合法，则默认为 ACM 规则
        rule_type = request.GET.get("rule")
        if rule_type not in ContestRuleType.choices():
            rule_type = ContestRuleType.ACM

        # 使用 select_related 提高查询性能，筛选出正常用户且未禁用的用户配置信息
        profiles = UserProfile.objects.filter(user__admin_type=AdminType.REGULAR_USER, user__is_disabled=False).select_related("user")

        # 根据比赛规则类型筛选并排序用户配置信息
        if rule_type == ContestRuleType.ACM:
            # 如果是 ACM 规则，筛选出提交次数大于 0 的用户，并按照通过题数降序、提交次数升序排序
            profiles = profiles.filter(submission_number__gt=0).order_by("-accepted_number", "submission_number")
        else:
            # 如果是 OI 规则，筛选出总分数大于 0 的用户，并按照总分数降序排序
            profiles = profiles.filter(total_score__gt=0).order_by("-total_score")

        # 使用 paginate_data 方法处理分页，并使用 RankInfoSerializer 序列化数据
        return self.success(self.paginate_data(request, profiles, RankInfoSerializer))

```

         - 这个视图适用于比赛中需要显示用户排名的场景，用户可以通过请求参数指定比赛规则类型，获取相应规则下的用户排名信息。
         - `paginate_data`不是自带的，是重写APIView里添加的
```python
def paginate_data(self, request, query_set, object_serializer=None):
    # 从请求中获取 limit 参数，表示每页返回的数据数量，默认为 10
    try:
        limit = int(request.GET.get("limit", "10"))
    except ValueError:
        limit = 10
    if limit < 0 or limit > 250:
        limit = 10

    # 从请求中获取 offset 参数，表示当前页的数据偏移，默认为 0
    try:
        offset = int(request.GET.get("offset", "0"))
    except ValueError:
        offset = 0
    if offset < 0:
        offset = 0

    # 根据 limit 和 offset 对 query_set 进行切片操作
    results = query_set[offset:offset + limit]

    # 如果提供了 object_serializer 参数，则使用序列化器对结果进行序列化
    if object_serializer:
        # 获取 query_set 的总数量
        count = query_set.count()
        # 使用序列化器对结果进行序列化
        results = object_serializer(results, many=True).data
    else:
        # 如果没有提供序列化器，则直接获取 query_set 的总数量
        count = query_set.count()

    # 构建返回的数据字典，包含分页后的结果和总数量
    data = {"results": results,
            "total": count}
    return data

```

            - 传入的参数为  **request**，**query_set**（Django model 的查询集（QuerySet）或其他类似列表的对象。这是你希望分页的数据集合），**object_serializer**（用来序列化查询集的序列化器。如果传入了序列化器，则对每页的数据进行序列化；如果为 None，则直接对查询集进行切片操作，不进行序列化）
      - **_会话管理_**（session_management_api）
```python
class SessionManagementAPI(APIView):
    @login_required
    # 这个方法用于获取当前用户的会话信息
    def get(self, request):
        # 这一行代码用于获取当前 Django 项目中配置的会话引擎
        engine = import_module(settings.SESSION_ENGINE)
        # 创建了一个会话存储对象，用于操作用户的会话数据。
        session_store = engine.SessionStore
        # 获取了当前用户的会话键，也就是用户浏览器中存储的会话标识符。
        current_session = request.session.session_key
        # 获取了当前用户的所有会话键的列表。这是一个与用户关联的会话信息。
        session_keys = request.user.session_keys
        # 存储结果的列表
        result = []
        # 记录是否有修改
        modified = False

        # 遍历当前用户的所有会话键
        for key in session_keys[:]:
            # 创建会话对象
            session = session_store(key)
            # 检查会话是否存在或已过期
            if not session._session:
                # 如果不存在或已过期，从用户的会话键列表中移除
                session_keys.remove(key)
                modified = True
                continue

            # 构建会话信息的字典
            s = {}
            # 判断是否是当前会话
            if current_session == key:
                s["current_session"] = True
            s["ip"] = session["ip"]
            s["user_agent"] = session["user_agent"]
            s["last_activity"] = datetime2str(session["last_activity"])
            s["session_key"] = key
            # 将当前会话信息添加到结果列表中
            result.append(s)

        # 如果有修改，保存用户对象
        if modified:
            request.user.save()

        # 返回结果列表
        return self.success(result)

    @login_required
    # 这个方法用于删除用户的特定会话
    def delete(self, request):
        # 获取要删除的会话键
        session_key = request.GET.get("session_key")
        if not session_key:
            return self.error("Parameter Error")

        # 删除指定会话键
        request.session.delete(session_key)

        # 如果该会话键在用户的会话键列表中，从列表中移除并保存用户对象
        if session_key in request.user.session_keys:
            request.user.session_keys.remove(session_key)
            request.user.save()
            return self.success("Succeeded")
        else:
            return self.error("Invalid session_key")
```

      - **_单点登录（SSO）_**
```python
class SSOAPI(CSRFExemptAPIView):
    @login_required
    def get(self, request):
        """
        获取令牌
        """
        # 生成随机令牌
        token = rand_str()
        # 将令牌与当前用户关联，并保存到数据库
        request.user.auth_token = token
        request.user.save()
        # 返回包含令牌的JSON响应
        return self.success({"token": token})

    @method_decorator(csrf_exempt)
    @validate_serializer(SSOSerializer)
    def post(self, request):
        """
        验证令牌
        """
        try:
            # 尝试从数据库中获取具有相应令牌的用户
            user = User.objects.get(auth_token=request.data["token"])
        except User.DoesNotExist:
            # 如果用户不存在，返回错误消息
            return self.error("User does not exist")
        
        # 返回包含用户信息的JSON响应
        return self.success({"username": user.username, "avatar": user.userprofile.avatar, "admin_type": user.admin_type})

```

         - 这个API可以用于构建单点登录系统，其中用户可以通过获取令牌的方式进行身份验证，然后在需要验证身份的其他系统中使用该令牌。这可以用于构建一种用户在一个系统中登录后，可以访问与该用户相关的其他系统而无需再次登录的机制。
   - admin.py
      - **_用户管理_**-导入用户、编辑用户、获取用户列表和删除用户等（user_admin_api）
```python
class UserAdminAPI(APIView):
    @validate_serializer(ImportUserSeralizer)
    @super_admin_required
    def post(self, request):
        """
        导入用户
        """
        # 从请求中获取用户数据
        data = request.data["users"]

        user_list = []
        for user_data in data:
            # 检查用户数据格式
            if len(user_data) != 4 or len(user_data[0]) > 32:
                return self.error(f"Error occurred while processing data '{user_data}'")
            # 创建 User 对象并添加到 user_list
            user_list.append(User(username=user_data[0], password=make_password(user_data[1]), email=user_data[2]))

        try:
            with transaction.atomic():
                # 使用 bulk_create 批量创建用户和用户配置信息
                ret = User.objects.bulk_create(user_list)
                UserProfile.objects.bulk_create([UserProfile(user=ret[i], real_name=data[i][3]) for i in range(len(ret))])
            return self.success()
        except IntegrityError as e:
            # 处理唯一性约束错误，例如用户名重复
            # 提取错误信息的详细部分
            return self.error(str(e).split("\n")[1])

    @validate_serializer(EditUserSerializer)
    @super_admin_required
    def put(self, request):
        """
        编辑用户
        """
        # 从请求中获取编辑用户的数据
        data = request.data
        try:
            # 根据用户id获取用户对象
            user = User.objects.get(id=data["id"])
        except User.DoesNotExist:
            return self.error("User does not exist")

        # 检查用户名和邮箱是否已存在
        if User.objects.filter(username=data["username"].lower()).exclude(id=user.id).exists():
            return self.error("Username already exists")
        if User.objects.filter(email=data["email"].lower()).exclude(id=user.id).exists():
            return self.error("Email already exists")

        pre_username = user.username
        # 更新用户信息
        user.username = data["username"].lower()
        user.email = data["email"].lower()
        user.admin_type = data["admin_type"]
        user.is_disabled = data["is_disabled"]

        if data["admin_type"] == AdminType.ADMIN:
            user.problem_permission = data["problem_permission"]
        elif data["admin_type"] == AdminType.SUPER_ADMIN:
            user.problem_permission = ProblemPermission.ALL
        else:
            user.problem_permission = ProblemPermission.NONE

        if data["password"]:
            user.set_password(data["password"])

        if data["open_api"]:
            # 避免在保存更改后重置用户 appkey
            if not user.open_api:
                user.open_api_appkey = rand_str()
        else:
            user.open_api_appkey = None
        user.open_api = data["open_api"]

        if data["two_factor_auth"]:
            # 避免在保存更改后重置用户 tfa_token
            if not user.two_factor_auth:
                user.tfa_token = rand_str()
        else:
            user.tfa_token = None

        user.two_factor_auth = data["two_factor_auth"]

        user.save()
        # 如果用户名发生变化，更新相关的提交记录
        if pre_username != user.username:
            Submission.objects.filter(username=pre_username).update(username=user.username)

        # 更新用户配置信息
        UserProfile.objects.filter(user=user).update(real_name=data["real_name"])
        return self.success(UserAdminSerializer(user).data)

    @super_admin_required
    def get(self, request):
        """
        用户列表 api / 通过 id 获取用户
        """
        # 根据用户id获取用户对象
        user_id = request.GET.get("id")
        if user_id:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return self.error("User does not exist")
            return self.success(UserAdminSerializer(user).data)

        # 获取所有用户并按创建时间倒序排列
        user = User.objects.all().order_by("-create_time")

        # 根据关键字过滤用户
        keyword = request.GET.get("keyword", None)
        if keyword:
            user = user.filter(Q(username__icontains=keyword) |
                               Q(userprofile__real_name__icontains=keyword) |
                               Q(email__icontains=keyword))
        return self.success(self.paginate_data(request, user, UserAdminSerializer))

    @super_admin_required
    def delete(self, request):
        id = request.GET.get("id")
        if not id:
            return self.error("Invalid Parameter, id is required")
        ids = id.split(",")
        if str(request.user.id) in ids:
            return self.error("Current user can not be deleted")
        # 批量删除用户
        User.objects.filter(id__in=ids).delete()
        return self.success()

```

      - 生成用户信息并提供下载用户信息的 Excel 文件（generate_user_api）
```python
class GenerateUserAPI(APIView):
    @super_admin_required
    def get(self, request):
        """
        download users excel
        """
        # 从请求中获取文件ID
        file_id = request.GET.get("file_id")
        if not file_id:
            return self.error("Invalid Parameter, file_id is required")
        if not re.match(r"^[a-zA-Z0-9]+$", file_id):
            return self.error("Illegal file_id")

        # 构造文件路径
        file_path = f"/tmp/{file_id}.xlsx"
        if not os.path.isfile(file_path):
            return self.error("File does not exist")

        # 读取文件内容
        with open(file_path, "rb") as f:
            raw_data = f.read()
        # 删除临时文件
        os.remove(file_path)

        # 构造 HTTP 响应，提供文件下载
        response = HttpResponse(raw_data)
        response["Content-Disposition"] = "attachment; filename=users.xlsx"
        response["Content-Type"] = "application/xlsx"
        return response

    @validate_serializer(GenerateUserSerializer)
    @super_admin_required
    def post(self, request):
        """
        Generate User
        """
        data = request.data
        number_max_length = max(len(str(data["number_from"])), len(str(data["number_to"])))

        # 检查用户名长度是否符合要求
        if number_max_length + len(data["prefix"]) + len(data["suffix"]) > 32:
            return self.error("Username should not be more than 32 characters")

        # 检查起始数字是否小于等于结束数字
        if data["number_from"] > data["number_to"]:
            return self.error("Start number must be lower than end number")

        # 生成文件ID和文件名
        file_id = rand_str(8)
        filename = f"/tmp/{file_id}.xlsx"

        # 创建 Excel 文件
        workbook = xlsxwriter.Workbook(filename)
        worksheet = workbook.add_worksheet()
        worksheet.set_column("A:B", 20)
        worksheet.write("A1", "Username")
        worksheet.write("B1", "Password")
        i = 1

        user_list = []
        # 循环生成用户信息
        for number in range(data["number_from"], data["number_to"] + 1):
            raw_password = rand_str(data["password_length"])
            user = User(username=f"{data['prefix']}{number}{data['suffix']}", password=make_password(raw_password))
            user.raw_password = raw_password
            user_list.append(user)

        try:
            with transaction.atomic():
                # 使用 bulk_create 批量创建用户和用户配置信息
                ret = User.objects.bulk_create(user_list)
                UserProfile.objects.bulk_create([UserProfile(user=user) for user in ret])

                # 将用户信息写入 Excel 文件
                for item in user_list:
                    worksheet.write_string(i, 0, item.username)
                    worksheet.write_string(i, 1, item.raw_password)
                    i += 1

                # 关闭并保存 Excel 文件
                workbook.close()
                return self.success({"file_id": file_id})
        except IntegrityError as e:
            # 处理唯一性约束错误，例如用户名重复
            # 提取错误信息的详细部分
            return self.error(str(e).split("\n")[1])

```
