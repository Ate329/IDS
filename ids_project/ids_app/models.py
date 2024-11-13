from django.db import models

class IDSStatus(models.Model):
    is_active = models.BooleanField(default=False)

class TrafficData(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    total_packets = models.IntegerField()
    normal_packets = models.IntegerField()
    anomaly_packets = models.IntegerField()
    protocol_type = models.CharField(max_length=10, default='unknown')
    flag = models.CharField(max_length=10, default='unknown')


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
    