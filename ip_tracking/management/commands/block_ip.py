# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand
from django.core.exceptions import ValidationError
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    help = "Block an IP address (add to BlockedIP blacklist)"

    def add_arguments(self, parser):
        parser.add_argument('ip', type=str, help='IP address to block (e.g. 192.168.1.1)')
        parser.add_argument(
            '--reason', '-r',
            type=str,
            default='',
            help='Optional reason for blocking'
        )

    def handle(self, *args, **options):
        ip_str = options['ip'].strip()
        reason = options['reason'].strip()

        # Validate IP format
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            self.stderr.write(self.style.ERROR(f"Invalid IP address: {ip_str}"))
            return

        # Try to create (or report if already exists)
        blocked, created = BlockedIP.objects.get_or_create(
            ip_address=str(ip_obj),
            defaults={'reason': reason}
        )

        if created:
            self.stdout.write(
                self.style.SUCCESS(f"Successfully blocked IP: {ip_str}")
            )
            if reason:
                self.stdout.write(f"Reason: {reason}")
        else:
            self.stdout.write(
                self.style.WARNING(f"IP {ip_str} is already blocked.")
            )