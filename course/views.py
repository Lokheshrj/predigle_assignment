# views.py
from rest_framework import viewsets, permissions, status,generics
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny,IsAuthenticated
from .models import User, Enrollment,Category, Course, Lesson, Module, Quiz, Question, Option, CorrectAnswer, Rating
from .serializers import UserLoginSerializer,UserSignUpSerializer,InstructorSignUpSerializer,AdminSignUpSerializer, UserSerializer, CategorySerializer, CourseSerializer, LessonSerializer, ModuleSerializer, QuizSerializer, QuestionSerializer, OptionSerializer, CorrectAnswerSerializer, RatingSerializer
from .permissions import IsAdminUserOnly,IsInstructorUserOnly,AndPermission  # Import the custom permission
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.db.models import Q
from .pagination_custom import CustomPagination
import logging
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler('app_log.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Check
def home(request):
    return HttpResponse("Welcome to the Home Page")

# User sign up
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the user'),
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the user'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
        },
        required=['email', 'name', 'password']
    ),
    responses={
        201: openapi.Response('User registered successfully'),
        400: openapi.Response('User signup failed'),
    }
)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def user_signup(request):
    serializer = UserSignUpSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info("User registered successfully")
        return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
    logger.error(f"User signup failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User login

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the user'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
        },
        required=['email', 'password']
    ),
    responses={
        200: openapi.Response('User login successful'),
        400: openapi.Response('Invalid email or password'),
    }
)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def user_login(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            logger.info("User login successful")
            return Response({"message": "User login successful"}, status=status.HTTP_200_OK)
        else:
            logger.error("Invalid email or password for user login")
            return Response({"message": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)
    logger.error(f"User login failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# List available categories
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_categories(request):
    categories = Category.objects.all()
    paginator = CustomPagination()
    result_page = paginator.paginate_queryset(categories, request)
    serializer = CategorySerializer(result_page, many=True)
    logger.info("Categories listed successfully")
    return paginator.get_paginated_response(serializer.data)

# View available courses by category

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter(
            name='category_id',
            in_=openapi.IN_PATH,
            type=openapi.TYPE_STRING,
            description='ID of the category',
            required=True,
        ),
    ],
    responses={
        200: openapi.Response('List of courses for the category', CourseSerializer(many=True)),
        404: openapi.Response('Category not found'),
    }
)


@api_view(['GET'])
@permission_classes([AllowAny])
def list_courses_by_category(request, category_id):
    logger.info(f"Received category_id: {category_id}")
    category = get_object_or_404(Category, pk=category_id)
    logger.info(f"Found category: {category.name}")
    courses = Course.objects.filter(category=category)
    paginator = CustomPagination()
    result_page = paginator.paginate_queryset(courses, request)
    serializer = CourseSerializer(result_page, many=True)
    logger.info(f"Courses listed successfully for category {category.name}")
    return paginator.get_paginated_response(serializer.data)

# Enroll in a course


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'course_id': openapi.Schema(type=openapi.TYPE_STRING, description='Course ID to get enrolled')
        },
        required=['course_id']
    ),
    responses={
        200: openapi.Response('Enrolled Successfully'),
        400: openapi.Response('Unexpected Error'),
    }
)


@api_view(['POST'])
@permission_classes([IsAuthenticated])

def enroll_course(request):
    user = request.user
    course_id = request.data.get('course_id')
    course = get_object_or_404(Course, pk=course_id)

    # Check if already enrolled
    if Enrollment.objects.filter(user=user, course=course).exists():
        logger.warning(f"User {user.email} already enrolled in course {course_id}")
        return Response({"message": "Already enrolled in this course"}, status=status.HTTP_400_BAD_REQUEST)

    enrollment = Enrollment(user=user, course=course)
    enrollment.save()
    logger.info(f"User {user.email} enrolled in course {course_id}")
    return Response({"message": "Enrolled in course successfully"}, status=status.HTTP_201_CREATED)

# View enrolled courses

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response('List of enrolled courses', CourseSerializer(many=True)),
        401: openapi.Response('Unauthorized, user not authenticated'),
    }
)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_enrolled_courses(request):
    user = request.user
    enrollments = Enrollment.objects.filter(user=user)
    courses = [enrollment.course for enrollment in enrollments]
    paginator = CustomPagination()
    result_page = paginator.paginate_queryset(courses, request)
    serializer = CourseSerializer(result_page, many=True)
    logger.info(f"User {user.email} listed enrolled courses")
    return paginator.get_paginated_response(serializer.data)

# Admin sign up

@swagger_auto_schema(
    method='post',
    request_body=AdminSignUpSerializer,
    responses={
        201: openapi.Response('Admin registered successfully'),
        400: openapi.Response('Bad request', examples={'application/json': {"email": ["This field is required."]}})
    }
)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_signup(request):
    serializer = AdminSignUpSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info("Admin registered successfully")
        return Response({"message": "Admin registered successfully"}, status=status.HTTP_201_CREATED)
    logger.error(f"Admin signup failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the user'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
        },
        required=['email', 'password']
    ),
    responses={
        200: openapi.Response('Login successful'),
        400: openapi.Response('Invalid email or password'),
    }
)
# Custom login
@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def custom_login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, username=email, password=password)  # Use 'username' instead of 'email'
    
    if user is not None:
        login(request, user)
        logger.info("Successfully logged in")
        return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
    else:
        logger.error("Invalid email or password")
        return Response({"message": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

# Create category

@swagger_auto_schema(
    method='post',
    request_body=CategorySerializer,
    responses={
        201: openapi.Response('Category created successfully', CategorySerializer),
        400: openapi.Response('Bad request', examples={'application/json': {"name": ["This field is required."]}})
    }
)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_category(request):
    serializer = CategorySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info("Category created successfully")
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    logger.error(f"Category creation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve categories (admin)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response('Categories retrieved successfully', CategorySerializer(many=True)),
        500: openapi.Response('Internal server error', examples={'application/json': {"error": "Error message"}})
    }
)

@api_view(['GET'])
@permission_classes([IsAdminUserOnly])
def retrieve_categories(request):
    try:
        categories = Category.objects.all()
        paginator = CustomPagination()
        result_page = paginator.paginate_queryset(categories, request)
        serializer = CategorySerializer(result_page, many=True)
        logger.info("Categories retrieved successfully")
        return paginator.get_paginated_response(serializer.data)
    except Exception as e:
        logger.error(f"Error retrieving categories: {e}")
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Retrieve single category (admin)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('pk', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_STRING)
    ],
    responses={
        200: openapi.Response('Category retrieved successfully', CategorySerializer()),
        404: openapi.Response('Category not found', examples={'application/json': {"detail": "Not found."}})
    }
)

@api_view(['GET'])
@permission_classes([IsAdminUserOnly])
def retrieve_category(request, pk):
    try:
        category = Category.objects.get(pk=pk)
    except Category.DoesNotExist:
        logger.warning(f"Category with pk {pk} not found")
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    # Get all courses related to this category
    courses = Course.objects.filter(category=category)
    paginator = CustomPagination()
    result_page = paginator.paginate_queryset(courses, request)
    
    # Serialize category and its paginated courses
    category_serializer = CategorySerializer(category)
    courses_serializer = CourseSerializer(result_page, many=True)
    
    response_data = {
        "category": category_serializer.data,
        "courses": paginator.get_paginated_response(courses_serializer.data).data
    }
    
    logger.info(f"Category with pk {pk} and its courses retrieved successfully")
    return Response(response_data)

# Update category (admin)
@swagger_auto_schema(
    method='put',
    manual_parameters=[
        openapi.Parameter('pk', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_STRING, required=True)
    ],
    request_body=CategorySerializer,
    responses={
        200: openapi.Response('Category updated successfully', CategorySerializer),
        400: openapi.Response('Invalid input', examples={'application/json': {"detail": "Bad Request"}}),
        404: openapi.Response('Category not found', examples={'application/json': {"detail": "Not found"}})
    }
)

@api_view(['PUT'])
@permission_classes([IsAdminUserOnly])
def update_category(request, pk):
    try:
        category = Category.objects.get(pk=pk)
    except Category.DoesNotExist:
        logger.warning(f"Category with pk {pk} not found")
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = CategorySerializer(category, data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info(f"Category with pk {pk} updated successfully")
        return Response(serializer.data)
    logger.error(f"Category update failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete category (admin)

@swagger_auto_schema(
    method='delete',
    manual_parameters=[
        openapi.Parameter('pk', openapi.IN_PATH, description="Category ID", type=openapi.TYPE_STRING)
    ],
    responses={
        204: openapi.Response('Category deleted successfully'),
        404: openapi.Response('Category not found', examples={'application/json': {"detail": "Not found"}})
    }
)

@api_view(['DELETE'])
@permission_classes([IsAdminUserOnly])
def delete_category(request, pk):
    try:
        category = Category.objects.get(pk=pk)
    except Category.DoesNotExist:
        logger.warning(f"Category with pk {pk} not found")
        return Response(status=status.HTTP_404_NOT_FOUND)

    category.delete()
    logger.info(f"Category with pk {pk} deleted successfully")
    return Response(status=status.HTTP_204_NO_CONTENT)

# Instructor sign up

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'name', 'password'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Instructor email'),
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='Instructor name'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
        },
    ),
    responses={
        201: openapi.Response('Instructor registered successfully'),
        400: openapi.Response('Bad request', examples={'application/json': {"detail": "Invalid data"}})
    }
)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def instructor_signup(request):
    serializer = InstructorSignUpSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        logger.info("Instructor registered successfully")
        return Response({"message": "Instructor registered successfully"}, status=status.HTTP_201_CREATED)
    logger.error(f"Instructor signup failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Instructor login

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'password'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Instructor email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
        },
    ),
    responses={
        200: openapi.Response('Instructor login successful'),
        400: openapi.Response('Bad request', examples={'application/json': {"detail": "Invalid credentials"}})
    }
)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def instructor_login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, email=email, password=password)
    if user is not None:
        login(request, user)
        logger.info("Instructor login successful")
        return Response({"message": "Instructor login successful"}, status=status.HTTP_200_OK)
    else:
        logger.error("Invalid email or password for instructor login")
        return Response({"message": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response('List of instructors'),
        500: openapi.Response('Internal server error', examples={'application/json': {"error": "Internal server error"}})
    }
)

@api_view(['GET'])
@permission_classes([AllowAny])
def list_instructors(request):
    instructors = User.objects.filter(role='instructor')
    paginator=CustomPagination()
    result_page = paginator.paginate_queryset(instructors, request)
    serializer = UserSerializer(result_page, many=True)
    logger.info("Instructors listed successfully")
    return paginator.get_paginated_response(serializer.data)

#course
class InstructorCourseViewSet(viewsets.ModelViewSet):
    serializer_class = CourseSerializer
    permission_classes = [permissions.IsAuthenticated, IsInstructorUserOnly]
    pagination_class = CustomPagination

    def get_queryset(self):
        return Course.objects.filter(instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['instructor','title', 'description', 'category'],
            properties={
                'instructor': openapi.Schema(type=openapi.TYPE_STRING, description='Instructor'),
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'category': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={
            201: openapi.Response('Created', CourseSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save(instructor=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            200: openapi.Response('OK', CourseSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def retrieve(self, request, pk=None):
        queryset = Course.objects.filter(instructor=self.request.user)
        course = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(course)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'description', 'category'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'category': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('OK', CourseSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def update(self, request, pk=None):
        queryset = Course.objects.filter(instructor=self.request.user)
        course = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(course, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def destroy(self, request, pk=None):
        queryset = Course.objects.filter(instructor=self.request.user)
        course = get_object_or_404(queryset, pk=pk)
        course.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        responses={
            200: openapi.Response('OK', CourseSerializer(many=True)),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        serializer = self.get_serializer(paginated_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)

#module
class InstructorModuleViewSet(viewsets.ModelViewSet):
    serializer_class = ModuleSerializer
    permission_classes = [IsInstructorUserOnly]
    pagination_class = CustomPagination

    def get_queryset(self):
        # Return modules filtered by the instructor
        return Module.objects.filter(course__instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'content', 'course'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'content': openapi.Schema(type=openapi.TYPE_STRING),
                'course': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', ModuleSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid course', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        course_id = data.get('course')
        if not course_id:
            return Response({"error": "Course ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure the course belongs to the logged-in instructor
        course = Course.objects.filter(id=course_id, instructor=request.user).first()
        if not course:
            return Response({"error": "Invalid course or not authorized."}, status=status.HTTP_403_FORBIDDEN)
        
        # Create the module
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            module = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            200: openapi.Response('OK', ModuleSerializer(many=True)),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        serializer = self.get_serializer(paginated_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)
#lesson
class InstructorLessonViewSet(viewsets.ModelViewSet):
    serializer_class = LessonSerializer
    permission_classes = [IsInstructorUserOnly]

    def get_queryset(self):
        # Return lessons filtered by the instructor's courses' modules
        return Lesson.objects.filter(module__course__instructor=self.request.user)


    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'content', 'module'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'content': openapi.Schema(type=openapi.TYPE_STRING),
                'module': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', LessonSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid module', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        module_id = data.get('module')
        if not module_id:
            return Response({"error": "Module ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure the module's course belongs to the logged-in instructor
        module = Module.objects.filter(module_id=module_id, course__instructor=self.request.user).first()
        if not module:
            return Response({"error": "Invalid module or not authorized."}, status=status.HTTP_403_FORBIDDEN)
        
        # Create the lesson
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            lesson = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'content', 'module'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'content': openapi.Schema(type=openapi.TYPE_STRING),
                'module': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('Updated', LessonSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid module', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        module_id = request.data.get('module')

        if module_id:
            module = Module.objects.filter(module_id=module_id, course__instructor=self.request.user).first()
            if not module:
                return Response({"error": "Invalid module or not authorized."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            lesson = serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
#quiz
class InstructorQuizViewSet(viewsets.ModelViewSet):
    serializer_class = QuizSerializer
    permission_classes = [IsInstructorUserOnly]  # Ensure this permission is correctly implemented

    def get_queryset(self):
        # Return quizzes filtered by the instructor's lessons' modules
        return Quiz.objects.filter(lesson__module__course__instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'description', 'lesson'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'lesson': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', QuizSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid lesson', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        lesson_id = data.get('lesson')
        if not lesson_id:
            return Response({"error": "Lesson ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        lesson = Lesson.objects.filter(lesson_id=lesson_id).first()
        if not lesson:
            return Response({"error": "Invalid lesson."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the quiz
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            quiz = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['title', 'description', 'lesson'],
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'lesson': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('Updated', QuizSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid lesson', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        lesson_id = request.data.get('lesson')

        if lesson_id:
            lesson = Lesson.objects.filter(lesson_id=lesson_id).first()
            if not lesson:
                return Response({"error": "Invalid lesson."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            quiz = serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
#questions
class InstructorQuestionViewSet(viewsets.ModelViewSet):
    serializer_class = QuestionSerializer
    permission_classes = [IsInstructorUserOnly]  # Ensure this permission is correctly implemented

    def get_queryset(self):
        # Return questions filtered by the instructor's quizzes' lessons' modules' courses
        return Question.objects.filter(quiz__lesson__module__course__instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['text', 'quiz'],
            properties={
                'text': openapi.Schema(type=openapi.TYPE_STRING),
                'quiz': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', QuestionSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid quiz', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        quiz_id = data.get('quiz')
        if not quiz_id:
            return Response({"error": "Quiz ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        quiz = Quiz.objects.filter(quiz_id=quiz_id).first()
        if not quiz:
            return Response({"error": "Invalid quiz."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the question
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            question = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['text', 'quiz'],
            properties={
                'text': openapi.Schema(type=openapi.TYPE_STRING),
                'quiz': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('Updated', QuestionSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid quiz', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        quiz_id = request.data.get('quiz')

        if quiz_id:
            quiz = Quiz.objects.filter(quiz_id=quiz_id).first()
            if not quiz:
                return Response({"error": "Invalid quiz."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            question = serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
#options
class InstructorOptionViewSet(viewsets.ModelViewSet):
    serializer_class = OptionSerializer
    permission_classes = [IsInstructorUserOnly]  # Ensure this permission is correctly implemented

    def get_queryset(self):
        # Return options filtered by the instructor's questions' quizzes' lessons' modules' courses
        return Option.objects.filter(question__quiz__lesson__module__course__instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['text', 'correct', 'question'],
            properties={
                'text': openapi.Schema(type=openapi.TYPE_STRING),
                'correct': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                'question': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', OptionSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid question', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        question_id = data.get('question')
        if not question_id:
            return Response({"error": "Question ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        question = Question.objects.filter(question_id=question_id).first()
        if not question:
            return Response({"error": "Invalid question."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the option
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            option = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['text', 'correct', 'question'],
            properties={
                'text': openapi.Schema(type=openapi.TYPE_STRING),
                'correct': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                'question': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('Updated', OptionSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid question', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        question_id = request.data.get('question')

        if question_id:
            question = Question.objects.filter(question_id=question_id).first()
            if not question:
                return Response({"error": "Invalid question."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            option = serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
#correctanswer
class InstructorCorrectAnswerViewSet(viewsets.ModelViewSet):
    serializer_class = CorrectAnswerSerializer
    permission_classes = [IsInstructorUserOnly]  # Ensure this permission is correctly implemented

    def get_queryset(self):
        # Return correct answers filtered by the instructor's questions' quizzes' lessons' modules' courses
        return CorrectAnswer.objects.filter(question__quiz__lesson__module__course__instructor=self.request.user)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['question', 'option'],
            properties={
                'question': openapi.Schema(type=openapi.TYPE_INTEGER),
                'option': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            201: openapi.Response('Created', CorrectAnswerSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid question/option', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        question_id = data.get('question')
        option_id = data.get('option')
        
        if not question_id:
            return Response({"error": "Question ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not option_id:
            return Response({"error": "Option ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        question = Question.objects.filter(question_id=question_id).first()
        option = Option.objects.filter(option_id=option_id).first()

        if not question:
            return Response({"error": "Invalid question."}, status=status.HTTP_400_BAD_REQUEST)
        if not option:
            return Response({"error": "Invalid option."}, status=status.HTTP_400_BAD_REQUEST)

        if option.question != question:
            return Response({"error": "The option does not belong to the question."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create the correct answer
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            correct_answer = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['question', 'option'],
            properties={
                'question': openapi.Schema(type=openapi.TYPE_INTEGER),
                'option': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: openapi.Response('Updated', CorrectAnswerSerializer),
            400: openapi.Response('Bad request', schema=None),
            403: openapi.Response('Permission denied or invalid question/option', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        question_id = request.data.get('question')
        option_id = request.data.get('option')

        if question_id:
            question = Question.objects.filter(question_id=question_id).first()
            if not question:
                return Response({"error": "Invalid question."}, status=status.HTTP_400_BAD_REQUEST)

        if option_id:
            option = Option.objects.filter(option_id=option_id).first()
            if not option:
                return Response({"error": "Invalid option."}, status=status.HTTP_400_BAD_REQUEST)

        if option and option.question != instance.question:
            return Response({"error": "The option does not belong to the question."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            correct_answer = serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            204: openapi.Response('No content', schema=None),
            404: openapi.Response('Not found', schema=None),
            500: openapi.Response('Internal server error', schema=None),
        }
    )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
#search by course
class CourseSearchView(generics.ListAPIView):
    serializer_class = CourseSerializer

    def get_queryset(self):
        queryset = Course.objects.all()
        title = self.request.query_params.get("q", None)
        if title:
            queryset = queryset.filter(title__icontains=title)  # Ensure 'Python' is in the title
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        course_data = []
        
        for course in queryset:
            course_serializer = self.get_serializer(course)
            course_info = course_serializer.data
            
            modules = Module.objects.filter(course=course)
            module_serializer = ModuleSerializer(modules, many=True)
            course_info['modules'] = module_serializer.data
            
            for module_data in course_info['modules']:
                module = Module.objects.get(module_id=module_data['module_id'])
                lessons = Lesson.objects.filter(module=module)
                lesson_serializer = LessonSerializer(lessons, many=True)
                module_data['lessons'] = lesson_serializer.data
                
                for lesson_data in module_data['lessons']:
                    lesson = Lesson.objects.get(lesson_id=lesson_data['lesson_id'])
                    quizzes = Quiz.objects.filter(lesson=lesson)
                    quiz_serializer = QuizSerializer(quizzes, many=True)
                    lesson_data['quizzes'] = quiz_serializer.data
                    
                    for quiz_data in lesson_data['quizzes']:
                        quiz = Quiz.objects.get(quiz_id=quiz_data['quiz_id'])
                        questions = Question.objects.filter(quiz=quiz)
                        question_serializer = QuestionSerializer(questions, many=True)
                        quiz_data['questions'] = question_serializer.data
                        
                        for question_data in quiz_data['questions']:
                            question = Question.objects.get(question_id=question_data['question_id'])
                            options = Option.objects.filter(question=question)
                            option_serializer = OptionSerializer(options, many=True)
                            question_data['options'] = option_serializer.data
            
            course_data.append(course_info)
        
        return Response(course_data, status=status.HTTP_200_OK)

#search by category

class CategorySearchView(generics.ListAPIView):
    serializer_class = CategorySerializer

    def get_queryset(self):
        queryset = Category.objects.all()
        category_name = self.request.query_params.get("q", None)
        if category_name:
            queryset = queryset.filter(name__icontains=category_name)
        return queryset

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'q',
                openapi.IN_QUERY,
                description='Filter categories by name containing this string',
                type=openapi.TYPE_STRING
            )
        ],
        responses={200: CategorySerializer(many=True)},
    )
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        category_data = []

        for category in queryset:
            category_serializer = self.get_serializer(category)
            category_info = category_serializer.data

            courses = Course.objects.filter(category=category)
            course_serializer = CourseSerializer(courses, many=True)
            category_info['courses'] = course_serializer.data

            for course_data in category_info['courses']:
                course = Course.objects.get(course_id=course_data['course_id'])
                modules = Module.objects.filter(course=course)
                module_serializer = ModuleSerializer(modules, many=True)
                course_data['modules'] = module_serializer.data

                for module_data in course_data['modules']:
                    module = Module.objects.get(module_id=module_data['module_id'])
                    lessons = Lesson.objects.filter(module=module)
                    lesson_serializer = LessonSerializer(lessons, many=True)
                    module_data['lessons'] = lesson_serializer.data

                    for lesson_data in module_data['lessons']:
                        lesson = Lesson.objects.get(lesson_id=lesson_data['lesson_id'])
                        quizzes = Quiz.objects.filter(lesson=lesson)
                        quiz_serializer = QuizSerializer(quizzes, many=True)
                        lesson_data['quizzes'] = quiz_serializer.data

                        for quiz_data in lesson_data['quizzes']:
                            quiz = Quiz.objects.get(quiz_id=quiz_data['quiz_id'])
                            questions = Question.objects.filter(quiz=quiz)
                            question_serializer = QuestionSerializer(questions, many=True)
                            quiz_data['questions'] = question_serializer.data

                            for question_data in quiz_data['questions']:
                                question = Question.objects.get(question_id=question_data['question_id'])
                                options = Option.objects.filter(question=question)
                                option_serializer = OptionSerializer(options, many=True)
                                question_data['options'] = option_serializer.data

            category_data.append(category_info)

        return Response(category_data, status=status.HTTP_200_OK)