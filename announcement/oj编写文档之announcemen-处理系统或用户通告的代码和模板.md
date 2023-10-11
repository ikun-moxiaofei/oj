- models文件：
```python
class Announcement(models.Model):
    title = models.TextField()
    # 它使用了一个富文本编辑器（可能是第三方库提供的 RichTextField），用于存储富文本内容，通常是 HTML。
    content = RichTextField()
    create_time = models.DateTimeField(auto_now_add=True)
    # 这一行定义了一个名为 created_by 的字段，是一个外键，与 User 模型关联，表示这个公告是由哪个用户创建的。
    # on_delete=models.CASCADE 意味着当关联的用户被删除时，相应的公告也会被删除。
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    last_update_time = models.DateTimeField(auto_now=True)
    visible = models.BooleanField(default=True)

    class Meta:
        db_table = "announcement"
        ordering = ("-create_time",)
```

- views文件：
   - oj.py
      - **_查看公告_**（announcement_api）
```python
class AnnouncementAPI(APIView):
    def get(self, request):
        announcements = Announcement.objects.filter(visible=True)
        return self.success(self.paginate_data(request, announcements, AnnouncementSerializer))

```

         - 用于查看可见的公告，同时使用了paginate_data自定义分页工具
   - admin.py
      - **_管理公告_**（announcement_admin_api）
```python
class AnnouncementAdminAPI(APIView):
    # 发布公告
    @validate_serializer(CreateAnnouncementSerializer)
    @super_admin_required
    def post(self, request):
        data = request.data
        # 创建公告对象
        announcement = Announcement.objects.create(
            title=data["title"],
            content=data["content"],
            created_by=request.user,
            visible=data["visible"]
        )
        # 返回成功响应并包含发布的公告信息
        return self.success(AnnouncementSerializer(announcement).data)

    # 编辑公告
    @validate_serializer(EditAnnouncementSerializer)
    @super_admin_required
    def put(self, request):
        data = request.data
        try:
            # 尝试获取要编辑的公告对象
            announcement = Announcement.objects.get(id=data.pop("id"))
        except Announcement.DoesNotExist:
            return self.error("公告不存在")

        # 更新公告对象的属性
        for k, v in data.items():
            setattr(announcement, k, v)
        announcement.save()

        # 返回成功响应并包含编辑后的公告信息
        return self.success(AnnouncementSerializer(announcement).data)

    # 获取公告列表或获取单个公告
    @super_admin_required
    def get(self, request):
        announcement_id = request.GET.get("id")
        if announcement_id:
            try:
                # 尝试获取单个公告对象
                announcement = Announcement.objects.get(id=announcement_id)
                return self.success(AnnouncementSerializer(announcement).data)
            except Announcement.DoesNotExist:
                return self.error("公告不存在")

        # 获取公告列表并按创建时间降序排序
        announcements = Announcement.objects.all().order_by("-create_time")
        
        # 如果指定获取可见的公告列表
        if request.GET.get("visible") == "true":
            announcements = announcements.filter(visible=True)

        # 返回成功响应并包含分页后的公告信息
        return self.success(self.paginate_data(request, announcements, AnnouncementSerializer))

    # 删除公告
    @super_admin_required
    def delete(self, request):
        if request.GET.get("id"):
            # 根据传递的 id 删除指定的公告
            Announcement.objects.filter(id=request.GET["id"]).delete()
        # 返回成功响应
        return self.success()

```

         - `super_admin_required`是自定义的权限认证工具，判断登录用户是否为管理员
```python
class super_admin_required(BasePermissionDecorator):
    def check_permission(self):
        user = self.request.user
        return user.is_authenticated and user.is_super_admin()

```

         - `setattr(announcement, k, v)`<br />setattr(announcement, k, v) 是 Python 内建函数 setattr 的调用。它用于设置对象的属性值，其中：announcement 是要设置属性的对象。k 是属性的名称（字符串），表示要设置的属性名。v 是要为属性设置的值。在上述代码的上下文中，setattr 被用于动态地为 announcement 对象设置属性。具体来说，它在编辑公告时用于更新公告对象的属性，将请求数据中的键值对（k 和 v）应用到 announcement 对象上。
