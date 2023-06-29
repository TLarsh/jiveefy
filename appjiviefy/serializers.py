from rest_framework import serializers
from .models import(
    Podcast,
    Category,
    RecordPodcast,
)

class PodcastSerializer(serializers.ModelSerializer):
    class Meta:
        model = Podcast
        fields = (
            "id",
            "user",
            "title",
            "get_absolute_url",
            "category",
            "description",
            "location",
            "get_image",
            "get_thumbnail"
        )
        read_only_fields = ("user",)
        
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)
        
        
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
    
    class Meta:
        model = RecordPodcast
        fields = (
            "id",
            "audio_record",
            "record_date"
        )