from django.urls import reverse
from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
import logging

from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import Application
from .serializers import ApplicationSerializer

from user.permissions import IsSuperUser, IsAdminOrSuperUser

logger = logging.getLogger(__name__)
User = get_user_model()

class ApplicationCreateView(generics.CreateAPIView):
    """
    Public endpoint to submit an application (Apply Now or Refer Someone).
    No authentication required. Notifies superusers by email when a new
    application is created.
    """
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        # Save the application object
        app = serializer.save()

        # Build a short summary for the email
        def safe_display(value):
            return str(value) if value is not None else ""

        summary_lines = [
            f"Applicant: {safe_display(app.full_name)}",
            f"Application type: {safe_display(app.application_type)}",
            f"Email: {safe_display(app.email)}",
            f"Phone: {safe_display(app.phone)}",
            f"Need housing when: {safe_display(app.need_housing_when)}",
            f"Living situation: {safe_display(app.living_situation)}",
            f"Income sources: {', '.join(app.income_sources) if app.income_sources else ''}",
            f"Has case manager: {safe_display(app.has_case_manager)}",
            f"Additional info: {safe_display(app.additional_info)}",
            f"Submitted at: {safe_display(app.created_at)}",
        ]
        summary_text = "\n".join(summary_lines)

        # Try to build an absolute admin link to the object change page
        admin_link = None
        try:
            # admin URL name: admin:<app_label>_<model_name>_change
            # app_label is the Django app name (your app is "appliction")
            admin_path = reverse('admin:appliction_application_change', args=(app.pk,))
            admin_link = self.request.build_absolute_uri(admin_path)
        except Exception:
            # fallback: relative admin path
            admin_link = f"/admin/appliction/application/{app.pk}/change/"

        subject = f"[New Application] {app.full_name}"
        text_body = f"A new application has been submitted:\n\n{summary_text}\n\nAdmin link: {admin_link}"
        html_body = (
            f"<p>A new application has been submitted:</p>"
            f"<pre style='white-space:pre-wrap'>{summary_text}</pre>"
            # f"<p><a href='{admin_link}'>Open in admin</a></p>"
        )

        # Collect superuser emails
        superuser_qs = User.objects.filter(is_active=True, is_superuser=True).exclude(email__isnull=True).exclude(email__exact="")
        recipient_list = list(superuser_qs.values_list("email", flat=True))

        # If there are no superusers with email, just log and return
        if not recipient_list:
            logger.warning("New application created but no superuser emails found to notify.")
            return

        # Use DEFAULT_FROM_EMAIL if set, otherwise fallback to settings.SERVER_EMAIL or empty
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(settings, "SERVER_EMAIL", None) or None

        # Send email (do not raise on failure)
        try:
            send_mail(
                subject=subject,
                message=text_body,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
                html_message=html_body,
            )
            logger.info("Notified superusers (%d) about new application id=%s", len(recipient_list), app.pk)
        except Exception as e:
            # Log exception but do not block the request/creation
            logger.exception("Failed to send new-application notification for application id=%s: %s", app.pk, e)


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