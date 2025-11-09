# ip_tracking/middleware.py
import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP
from django_ip_geolocation.geolocation import Geolocation

logger = logging.getLogger('request_logger')


class RequestLoggingMiddleware:
    CACHE_TTL = 24 * 60 * 60  # 24 hours
    CACHE_KEY_PREFIX = "geo:ip:"

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

        # ---------- GEOLOCATION + LOG ----------
        geo_data = self._get_geolocation(ip)
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            country=geo_data.get('country'),
            city=geo_data.get('city'),
        )
        logger.info(
            "IP=%s | %s, %s | %s",
            ip,
            geo_data.get('city') or 'Unknown',
            geo_data.get('country') or 'Unknown',
            path
        )

        return response

    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or '0.0.0.0'

    def _get_geolocation(self, ip):
        """
        Fetch geolocation via django-ip-geolocation.
        Cache result for 24 hours.
        """
        # Skip localhost
        if ip in ['127.0.0.1', '::1', '0.0.0.0']:
            return {'country': None, 'city': None}

        cache_key = f"{self.CACHE_KEY_PREFIX}{ip}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        try:
            geo = Geolocation(ip)
            data = {
                'country': geo.country_name,
                'city': geo.city,
            }
        except Exception as e:
            logger.error("Geolocation failed for %s: %s", ip, e)
            data = {'country': None, 'city': None}

        cache.set(cache_key, data, timeout=self.CACHE_TTL)
        return data