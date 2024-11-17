from django.db import models

class IDSStatus(models.Model):
    is_active = models.BooleanField(default=False)

class TrafficData(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    total_packets = models.IntegerField(default=0)
    normal_packets = models.IntegerField(default=0)
    anomaly_packets = models.IntegerField(default=0)

class EmailSettings(models.Model):
    email_sender = models.EmailField(default="default@example.com")
    email_password = models.CharField(max_length=255)
    email_recipient = models.EmailField(default="recipient@example.com")
    smtp_server = models.CharField(max_length=255, default="smtp.example.com")
    smtp_port = models.IntegerField(default=587)


class IDSSettings(models.Model):
    detect_internal = models.BooleanField(default=False)

    @classmethod
    def get_settings(cls):
        return cls.objects.first() or cls.objects.create()
    