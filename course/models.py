from djongo import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, role='student'):
        if not email:
            raise ValueError("Users must have an email address")
        if not name:
            raise ValueError("Users must have a name")
        
        user = self.model(
            email=self.normalize_email(email),
            name=name,
            role=role
        )
        
        if password:
            user.set_password(password)
        
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        user = self.create_user(
            email=email,
            name=name,
            password=password,
            role='admin'
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=[('student', 'Student'), ('instructor', 'Instructor'), ('admin', 'Admin')])

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'role']

    def __str__(self):
        return self.email

    @property
    def is_staff(self):
        return self.role == 'admin'

    @property
    def is_superuser(self):
        return self.role == 'admin'

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

class Category(models.Model):
    category_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'categories'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'

    def __str__(self):
        return self.name

class Course(models.Model):
    course_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    instructor = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'instructor'})
    category = models.ForeignKey(Category, on_delete=models.CASCADE)

    class Meta:
        db_table = 'courses'

    def __str__(self):
        return self.title
    
class Enrollment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    course = models.ForeignKey('Course', on_delete=models.CASCADE)
    enrolled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'course')

    def __str__(self):
        return f"{self.user.email} enrolled in {self.course.name}"


class Lesson(models.Model):
    lesson_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module = models.ForeignKey('Module', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    content = models.TextField()

    class Meta:
        db_table = 'lessons'

    def __str__(self):
        return self.title

class Module(models.Model):
    module_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField()

    class Meta:
        db_table = 'modules'

    def __str__(self):
        return self.title

class Quiz(models.Model):
    quiz_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE)

    def __str__(self):
        return f"Quiz for {self.lesson.title}"

class Question(models.Model):
    question_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    question_text = models.TextField()

    def __str__(self):
        return self.question_text

class Option(models.Model):
    option_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='options')
    option_text = models.CharField(max_length=255)

    def __str__(self):
        return self.option_text

class CorrectAnswer(models.Model):
    correct_answer_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    question = models.OneToOneField(Question, on_delete=models.CASCADE, related_name='correct_answer')
    option = models.OneToOneField(Option, on_delete=models.CASCADE)

    def __str__(self):
        return f"Correct answer for {self.question.question_text}"

class Rating(models.Model):
    rating_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'student'})
    rating = models.IntegerField(choices=[(i, str(i)) for i in range(1, 6)])
    comment = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'ratings'

    def __str__(self):
        return f"{self.rating} by {self.user.email} for {self.course.title}"
