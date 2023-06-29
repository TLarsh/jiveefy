from . import views
from django.urls import path

urlpatterns = [
    path('podcasts/recommended/', views.RecommendedPostsView.as_view(), name='recommended-posts'),
    path('podcasts/viewed/', views.ViewedPostsView.as_view(), name='viewed-posts'),
    path('publish-podcast/', views.PublishPodcastView.as_view(), name='publish-podcast'),
    path('latest-podcasts/', views.LatestPodcastsListView.as_view(), name='latest-podcasts'),
    path('featured-podcasts/', views.FeaturedPodcastsListView.as_view(), name='featured-podcasts'),
    path('record-audio/', views.AudioRecordView.as_view(), name='record-audio'),
    path('audio/records/', views.AudioRecListView.as_view(), name='audios'),
    path('audio/record/<pk>/', views.AudioRecordView.as_view(), name='audio'),
    path('podcasts/', views.PodcastsListView.as_view(), name='podcasts'),
    path('podcasts/search/', views.PodcastSearchView.as_view(), name='search'),
    path('podcasts/<slug:category_slug>/<slug:podcast_slug>/', views.PodcastDetail.as_view()),
    path('podcasts/<slug:category_slug>/', views.CategoryDetail.as_view()),
]