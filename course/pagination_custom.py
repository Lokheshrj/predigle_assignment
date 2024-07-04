# custom_pagination.py
from rest_framework.pagination import PageNumberPagination

class CustomPagination(PageNumberPagination):
    page_size = 5  # Number of items per page
    page_size_query_param = 'page_size'
    max_page_size = 100
