from account.decorators import super_admin_required
from utils.api import APIView, validate_serializer

from announcement.models import Announcement
from announcement.serializers import (AnnouncementSerializer, CreateAnnouncementSerializer,
                                      EditAnnouncementSerializer)


class AnnouncementAdminAPI(APIView):
    @validate_serializer(CreateAnnouncementSerializer)
    @super_admin_required
    def post(self, request):
        """
        publish announcement
        """
        data = request.data
        announcement = Announcement.objects.create(title=data["title"],
                                                   content=data["content"],
                                                   created_by=request.user,
                                                   visible=data["visible"])
        return self.success(AnnouncementSerializer(announcement).data)

    @validate_serializer(EditAnnouncementSerializer)
    @super_admin_required
    def put(self, request):
        """
        edit announcement
        """
        data = request.data
        try:
            announcement = Announcement.objects.get(id=data.pop("id"))
        except Announcement.DoesNotExist:
            return self.error("Announcement does not exist")

        for k, v in data.items():
            setattr(announcement, k, v)
        announcement.save()

        return self.success(AnnouncementSerializer(announcement).data)

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
