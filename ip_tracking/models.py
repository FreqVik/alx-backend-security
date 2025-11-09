from django.db import models

# Create your models here.
class RequestLog(models.Model):
    """
    db models for requests
    """
    ip_address = models.GenericIPAddressField(protocol='both', unpack_ipv4=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)


    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    Stores IP addresses that should be blocked (403 Forbidden).
    """
    ip_address = models.GenericIPAddressField(
        protocol='both',
        unpack_ipv4=True,
        unique=True,
    )
    added_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=200, blank=True)

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-added_at']

    def __str__(self):
        return f"{self.ip_address} ({self.reason or 'no reason'})"
    

class SuspiciousIP(models.Model):
    """
    IPs flagged by anomaly detection.
    """
    ip_address = models.GenericIPAddressField(protocol='both', unpack_ipv4=True, unique=True)
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)
    is_blocked = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-flagged_at']

    def __str__(self):
        return f"{self.ip_address} – {self.reason}"