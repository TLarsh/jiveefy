from django.contrib import admin

from appjiviefy.models import Category, Podcast, RecordPodcast, ViewHistory

# Register your models here.
admin.site.register(Category)
admin.site.register(Podcast)
admin.site.register(RecordPodcast)
admin.site.register(ViewHistory)