from django.db import models
from io import BytesIO
from PIL import Image
from django.core.files import File
from django.contrib.auth import get_user_model
User = get_user_model()

# Create your models here.


class Category(models.Model):
    name = models.CharField(max_length=50)
    slug = models.SlugField() 

    class Meta:
        ordering = ('name',)
        
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        return f'/{self.slug}/'
    
    

    
        
class Podcast(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=100, blank=True, null=True)
    category = models.ForeignKey(Category, related_name='podcasts', on_delete=models.CASCADE)
    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=50)
    slug = models.SlugField()
    image = models.ImageField(upload_to='uploads/', blank=True, null=True)
    thumbnail = models.ImageField(upload_to='uploads/', blank=True, null=True)
    is_featured = models.BooleanField(default=False)

    date_added = models.DateTimeField(auto_now_add=True)
    
    
    class Meta:
        ordering = ('-date_added',)

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return f'/{self.category.slug}/{self.slug}/'

    def get_image(self):
        if self.image:
            return 'http//:127.0.0.1:8000' + self.image.url
        return ''

    def get_thumbnail(self):
        if self.thumbnail:
            return 'http//:127.0.0.1:8000' + self.thumbnail.url
        else:
            if self.image:
                self.thumbnail = self.make_thumbnail(self.image)
                self.save()
                return 'ht tp//:127.0.0.1:8000' + self.thumbnail.url
            else:
                return ''

    def make_thumbnail(self, image, size=(800, 800)):
        img = Image.open(image)
        img.convert("RGB")
        img.thumbnail(size)

        thumb_io = BytesIO()
        img.save(thumb_io, format='JPEG', quality=85)

        thumbnail = File(thumb_io, name=image.name)

        return thumbnail
    
    
class RecordPodcast(models.Model):
    audio_record = models.FileField(upload_to = 'uploads/%y/%m/%d')
    record_date = models.DateTimeField(auto_now_add=True)
    