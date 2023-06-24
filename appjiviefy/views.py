
from operator import truediv
from urllib import response
from django.shortcuts import render
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.decorators import api_view
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from rest_framework import permissions
from django.http import Http404
from .models import(
    Podcast,
    Category,
    RecordPodcast
)
from .serializers import(
    PodcastSerializer,
    CategorySerializer,
    AudioRecordSerializer
)
from appjiviefy import serializers


# Create your views here.
class PublishPodcastView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    def post(self, request, format=None):
        # Podcast = Podcast.objects.all()
        data = self.request.data
        user = request.user
        title =  data['title']
        description = data['description']
        category = data['category']
        location = data['location']
        # slug = data['slug']
        image = data['image']
        cat=Category.objects.create(name=category, slug=category.replace(" ", "_"))
        cat.save()
        pod=Podcast.objects.create(user=user, title=title, description=description, category=cat,
                               location=location, slug=title.replace(" ", "_"), image=image)
        pod.save()
        
        serializer = PodcastSerializer(pod)
        return Response(serializer.data)


class LatestPodcastsListView(ListAPIView):
    # def get(self, request, format=None):
    permission_classes = (permissions.AllowAny,)
    queryset = Podcast.objects.all()
    serializer_class = PodcastSerializer
    # return Response(serializer.data)
    
class PodcastsListView(ListAPIView):
    # def get(self, request, format=None):
    permission_classes = (permissions.AllowAny,)
    queryset = Podcast.objects.all()[0:2]
    serializer_class = PodcastSerializer
    
    
class FeaturedPodcastsListView(ListAPIView):
    # def get(self, request, format=None):
    permission_classes = (permissions.AllowAny,)
    queryset = Podcast.objects.order_by('-date_added').filter(is_featured=True)
    serializer_class = PodcastSerializer
    
    
class PodcastDetail(APIView):
    permission_classes = (permissions.AllowAny,)
    def get_object(self, category_slug, podcast_slug, many=True):
        try:
            return Podcast.objects.filter(category__slug=category_slug).get(slug=podcast_slug)
        except Podcast.DoesNotExist:
            raise Http404

    def get(self, request, podcast_slug, category_slug, format=None):
        podcast = self.get_object(category_slug, podcast_slug)
        serializer = PodcastSerializer(podcast)
        return Response(serializer.data)

class CategoryDetail(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def get_object(self, category_slug):
        try:
            return Category.objects.get(slug=category_slug)
        except Podcast.DoesNotExist:
            raise Http404

    def get(self, request, category_slug, format=None):
        category = self.get_object(category_slug)
        serializer = CategorySerializer(category)
        return Response(serializer.data)
    

class PodcastSearchView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_classes = (PodcastSerializer)

    def post(self, request, format=None):
        queryset = Podcast.objects.order_by('-date_added')
        data = self.request.data
        
        location = data['location']
        queryset = queryset.filter(location__iexact=location)
        
        category = data['category']
        queryset = queryset.filter(category__name=category)
        
        keywords = data['keywords']
        queryset = queryset.filter(description__icontains=keywords)
        
        serializer = PodcastSerializer(queryset, many=True)
        return Response(serializer.data)
    
# class CategorySearchView(APIView):
#     permission_classes = (permissions.AllowAny,)
#     def post(self, request, format=None):
#         queryset = Podcast.objects.order_by('-date_added')
#         data = self.request.data
#         category = data['category']
#         queryset = queryset.filter(category__name=category)
#         serializer = PodcastSerializer(queryset, many=True)
#         return Response(serializer.data)
    
    
# class CategorySearchView(APIView):
#     permission_classes = (permissions.AllowAny,)
#     def post(self, request, format=None):
#         queryset = Category.objects.order_by('-name')
#         data = self.request.data
#         category = data['category']
#         queryset = queryset.filter(name__iexact=category)
#         serializer = CategorySerializer(queryset, many=True)
#         return Response(serializer.data)
    

# @api_view(['POST'])
# @permission_classes([permissions.AllowAny])
# def search(request):
#     query = request.data.get('query', '')
#     if query:
#         podcasts = Podcast.objects.filter(Q(title__icontains=query) | Q(description__icontains=query))
#         serializer = PodcastSerializer(podcasts, many=True)
#         return Response(serializer.data)
#     else:
#         return Response({"podcasts": []})


class AudioRecordView(APIView):
    def post(self, request, format=None):
        data = self.request.data
        audio_record = data['audio_record']
        rec = RecordPodcast.objects.create(audio_record = audio_record)
        rec.save()
        serializer = AudioRecordSerializer(rec)
        return Response({
            "Audio file successfully created",
            serializer.data
        })
