from . import views
from django.urls import path

urlpatterns = [
    path('publish-podcast/', views.PublishPodcastView.as_view()),
    path('latest-podcasts/', views.LatestPodcastsListView.as_view()),
    path('featured-podcasts/', views.FeaturedPodcastsListView.as_view()),
    path('podcasts/', views.PodcastsListView.as_view()),
    # path('podcasts/search/', views.search),
    path('podcasts/search/', views.PodcastSearchView.as_view()),
    # path('podcasts/search/category-search/', views.CategorySearchView.as_view()),
    path('podcasts/<slug:category_slug>/<slug:podcast_slug>/', views.PodcastDetail.as_view()),
    path('podcasts/<slug:category_slug>/', views.CategoryDetail.as_view()),
]