from celery import shared_task
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login', '/admin/', '/login/']
HIGH_REQUEST_THRESHOLD = 100


@shared_task
def detect_suspicious_ips():
    """
    Runs hourly.
    Flags:
      1. >100 requests in the last hour
      2. Any access to /admin or /login
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    high_volume = (
        recent_logs
        .values('ip_address')
        .annotate(count=Count('ip_address'))
        .filter(count__gt=HIGH_REQUEST_THRESHOLD)
    )

    sensitive_access = recent_logs.filter(
        Q(path__istartswith='/admin') | Q(path__istartswith='/login')
    ).values_list('ip_address', flat=True).distinct()

    suspicious_ips = set()

    for entry in high_volume:
        ip = entry['ip_address']
        reason = f"Exceeded {HIGH_REQUEST_THRESHOLD} requests/hour ({entry['count']} requests)"
        suspicious_ips.add((ip, reason))

    for ip in sensitive_access:
        reason = "Accessed sensitive path (/admin or /login)"
        suspicious_ips.add((ip, reason))

    created_count = 0
    for ip, reason in suspicious_ips:
        obj, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': reason}
        )
        if created:
            created_count += 1
        else:
            if obj.reason != reason:
                obj.reason = reason
                obj.save()

    return f"Detected {len(suspicious_ips)} suspicious IPs ({created_count} new)"