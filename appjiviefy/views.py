
from urllib import response
from django.shortcuts import render
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView, CreateAPIView
from rest_framework.decorators import api_view
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from rest_framework import permissions
from django.http import Http404
from .models import(
    Podcast,
    Category,
    RecordPodcast,
    ViewHistory
)
from .serializers import(
    PodcastSerializer,
    CategorySerializer,
    AudioRecordSerializer
)
from appjiviefy import serializers


# Create your views here.
class PublishPodcastView(CreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Podcast.objects.all()
    serializer_class = PodcastSerializer
    def create(self, request, *args, **kwargs):
        # user = request.user
        category_name = request.data.get('category')
        if category_name:
            category, _ = Category.objects.get_or_create(name=category_name)
            request.data['category'] = category.id

        return super().create(request, *args, **kwargs)
    # def post(self, request, format=None):
    #     # Podcast = Podcast.objects.all()
    #     data = self.request.data
    #     user = request.user
    #     title =  data['title']
    #     description = data['description']
    #     category = data['category']
    #     location = data['location']
    #     # slug = data['slug']
    #     image = data['image']
    #     cat=Category.objects.create(name=category)
    #     cat.save()
    #     pod=Podcast.objects.create(user=user, title=title, description=description, category=cat,
    #                            location=location, image=image)
    #     pod.save()
        
    #     serializer = PodcastSerializer(pod)
    #     return Response(serializer.data)


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
        ViewHistory.objects.create(user=request.user, podcast=podcast)
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
    #     queryset = Podcast.objects.order_by('-date_added')
        data = self.request.data
        
    #     location = data['location']
    #     queryset = queryset.filter(location__iexact=location)
        
    #     category = data['category']
    #     queryset = queryset.filter(category__name=category)
        
    #     keywords = data['keywords']
    #     queryset = queryset.filter(description__icontains=keywords)
        
    #     serializer = PodcastSerializer(queryset, many=True)
    #     return Response(serializer.data)
        category = data['category']
        location = data['location']
        keywords = data['keywords']

        # Filter posts based on the provided search criteria
        queryset = Podcast.objects.all()

        if category:
            queryset = queryset.filter(category__name=category)

        if location:
            queryset = queryset.filter(location__iexact=location)

        if keywords:
            queryset = queryset.filter(description__icontains=keywords)

        # Serialize the filtered posts and return as a response
        serialized_posts = PodcastSerializer(queryset, many=True)
        return Response(serialized_posts.data)

class RecommendedPostsView(APIView):
    def get(self, request):
        user = request.user
        recommended_posts = self.generate_recommended_posts(user)
        serialized_posts = PodcastSerializer(recommended_posts, many=True)
        return Response(serialized_posts.data)

    def generate_recommended_posts(self, user):
        # Retrieve user preferences or any relevant data
        user_preferences = user.preferences

        # Query posts based on relevant criteria
        posts = Podcast.objects.filter(category=user_preferences.category)

        # Calculate post scores based on criteria (e.g., popularity, similarity, etc.)
        scored_posts = []
        for post in posts:
            score = self.calculate_post_score(post, user)
            scored_posts.append((post, score))

        # Sort the scored posts by score in descending order
        sorted_posts = sorted(scored_posts, key=lambda x: x[1], reverse=True)

        # Select top-ranked posts as recommendations
        top_posts = [post[0] for post in sorted_posts[:5]]  # Get top 5 posts

        return top_posts

    def calculate_post_score(self, post, user):
        # Implement your score calculation logic here
        # You can consider factors like post popularity, similarity, etc.
        # Use user preferences or behavior to influence the scores
        score = 0

        # Example: Increase score if the post's category matches user preferences
        if post.category == user.preferences.category:
            score += 1

        return score
    
    
class ViewedPostsView(APIView):
    def get(self, request):
        # Retrieve the user's ID
        user_id = request.user.id

        # Retrieve the viewed posts for the user
        viewed_posts = ViewHistory.objects.filter(user_id=user_id)

        # Extract the post instances from the view history
        posts = [view.podcast for view in viewed_posts]

        # Serialize the posts and return as a response
        serialized_posts = PodcastSerializer(posts, many=True)
        return Response(serialized_posts.data)
    

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
        
        
class AudioRecListView(ListAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = RecordPodcast.objects.all()
    serializer_class = AudioRecordSerializer
    
    
class AudioRecView(RetrieveAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = RecordPodcast.objects.all()
    serializer_class = AudioRecordSerializer
