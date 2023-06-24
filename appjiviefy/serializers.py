from rest_framework import serializers
from .models import(
    Podcast,
    Category
)

class PodcastSerializer(serializers.ModelSerializer):
    class Meta:
        model = Podcast
        fields = (
            "id",
            "title",
            "get_absolute_url",
            "category",
            "description",
            "location",
            "get_image",
            "get_thumbnail"
        )
        
        
class CategorySerializer(serializers.ModelSerializer):
    podcasts = PodcastSerializer(many=True)
    
    class Meta:
        model = Category
        fields = (
            "id",
            "name", 
            "get_absolute_url",
            "podcasts",
        )
        
class AudioRecordSerializer(serializers.ModelSerializer):
    podcasts = PodcastSerializer(many=True)
    
    class Meta:
        model = Category
        fields = (
            "id",
            "name", 
            "get_absolute_url",
            "podcasts",
        )