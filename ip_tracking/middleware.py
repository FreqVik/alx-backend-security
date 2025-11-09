# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

logger = logging.getLogger('request_logger')


class RequestLoggingMiddleware:
    """
    1. Blocks blacklisted IPs (403)
    2. Logs request (uses request.geolocation from django-ip-geolocation)
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self._get_client_ip(request)
        path = request.path

        # ---------- BLOCK CHECK ----------
        if BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning("BLOCKED IP %s attempted %s", ip, path)
            return HttpResponseForbidden("Access denied: Your IP is blocked.")

        # ---------- PROCESS REQUEST ----------
        response = self.get_response(request)

        # ---------- LOG + GEOLOCATION (from django-ip-geolocation) ----------
        geo = getattr(request, 'geolocation', None)
        country = geo.country_name if geo else None
        city = geo.city if geo else None

        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            country=country,
            city=city,
        )
        logger.info("IP=%s | %s, %s | %s", ip, city or 'Unknown', country or 'Unknown', path)

        return response

    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or '0.0.0.0'