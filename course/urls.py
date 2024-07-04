from django.urls import path, include,re_path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .  import views
from .views import (
    admin_signup, instructor_login, home, custom_login, user_signup, user_login, list_categories, list_courses_by_category,
    enroll_course, list_enrolled_courses, InstructorModuleViewSet, CategorySearchView,
    InstructorCourseViewSet, InstructorLessonViewSet, InstructorQuizViewSet, InstructorQuestionViewSet,
    InstructorOptionViewSet, InstructorCorrectAnswerViewSet, CourseSearchView
)

schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation",
        default_version='v1',
        description="API documentation for the project",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
    authentication_classes=[],
)

swagger_settings = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT Authorization header using the Bearer scheme. Example: "Authorization: Bearer {token}"',
        }
    }
}

instructor_router = DefaultRouter()
instructor_router.register(r'instructor/courses', InstructorCourseViewSet, basename='instructor-course')
instructor_router.register(r'instructor/modules', InstructorModuleViewSet, basename='instructor-module')
instructor_router.register(r'instructor/lessons', InstructorLessonViewSet, basename='instructor-lesson')
instructor_router.register(r'instructor/quiz', InstructorQuizViewSet, basename='instructor-quiz')
instructor_router.register(r'instructor/questions', InstructorQuestionViewSet, basename='instructor-question')
instructor_router.register(r'instructor/options', InstructorOptionViewSet, basename='instructor-option')
instructor_router.register(r'instructor/correct-answers', InstructorCorrectAnswerViewSet, basename='instructor-correct-answer')

admin_paths = [
    path('signup/', admin_signup, name='admin-signup'),
    path('login/', custom_login, name='custom-login'),
    path('categories/', views.retrieve_categories, name='retrieve-categories'),
    path('categories/create/', views.create_category, name='create-category'),
    path('categories/<uuid:pk>/courses', views.retrieve_category, name='retrieve-category'),
    path('categories/update/<uuid:pk>/', views.update_category, name='update-category'),
    path('categories/delete/<uuid:pk>/', views.delete_category, name='delete-category'),
]

search_paths = [
    path('categories/', CategorySearchView.as_view(), name='category-search'),
    path('courses/', CourseSearchView.as_view(), name='course-search'),
]

instructor_paths = [
    path('login/', instructor_login, name='instructor-login'),
    path('signup/', views.instructor_signup, name='instructor-signup'),
    path('', views.list_instructors, name='list-instructors')
]

token_paths = [
    path('', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh')
]

user_paths = [
    path('signup/', user_signup, name='user_signup'),
    path('login/', user_login, name='user_login'),
    path('categories/', list_categories, name='list_categories'),
    path('categories/<uuid:category_id>', list_courses_by_category, name='list_courses_by_category'),
    path('enroll/', enroll_course, name='enroll_course'),
    path('enrolled-courses/', list_enrolled_courses, name='list_enrolled_courses'),
]

urlpatterns = [
    path('', home, name='home'),
    path('admin/', include((admin_paths, 'admin'))),
    path('search/', include((search_paths, 'search'))),
    path('api/token/', include((token_paths, 'api/token'))),
    path('instructor/', include((instructor_paths, 'instructor'))),
    path('user/', include((user_paths, 'user'))),
    path('', include(instructor_router.urls)),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
