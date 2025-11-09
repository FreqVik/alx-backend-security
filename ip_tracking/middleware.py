# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

logger = logging.getLogger('request_logger')


class RequestLoggingMiddleware:
    """
    1. Logs every request (IP, timestamp, path)
    2. Blocks requests from IPs in BlockedIP → 403
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self._get_client_ip(request)
        path = request.path

        # ---------- BLOCK CHECK ----------
        if BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning("BLOCKED IP %s attempted %s", ip, path)
            return HttpResponseForbidden(
                "Access denied: Your IP is blocked."
            )

        # ---------- PROCESS REQUEST ----------
        response = self.get_response(request)

        # ---------- LOG AFTER SUCCESS ----------
        RequestLog.objects.create(ip_address=ip, path=path)
        logger.info("IP=%s | PATH=%s", ip, path)

        return response

    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or '0.0.0.0'