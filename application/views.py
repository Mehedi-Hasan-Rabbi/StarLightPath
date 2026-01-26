from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import Application
from .serializers import ApplicationSerializer

from user.permissions import IsSuperUser, IsAdminOrSuperUser


class ApplicationCreateView(generics.CreateAPIView):
    """
    Public endpoint to submit an application (Apply Now or Refer Someone).
    No authentication required.
    """
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [AllowAny]


class ApplicationListView(generics.ListAPIView):
    """
    Admin-only listing of applications.
    """
    queryset = Application.objects.all().order_by("-created_at")
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]


class ApplicationDetailView(generics.RetrieveAPIView):
    """
    Admin-only retrieve single application.
    """
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]