from django.db import models


class TimeStampedManager(models.Manager):
    def get_queryset(self):
        return super(TimeStampedManager, self).get_queryset().filter(deleted_at__isnull=True)


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    objects = TimeStampedManager()

    class Meta:
        abstract = True
