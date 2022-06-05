from rest_framework import generics, permissions
from .serializers import TodoSerializer, TodoToggleCompleteSerializer
from todo.models import Todo
from django.db import IntegrityError
from django.contrib.auth.models import User
from rest_framework.parsers import JSONParser
from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate


class TodoListCreate(generics.ListCreateAPIView):
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]

    # IsAuthenticatedOrReadOnly - разрешить просмотр страницы или модели какого-то юзера для неаунтефицированных пользователей
    # IsAdminUser - доступ имеет только администратор(суперпользователи)
    # AllowAny - любой пользователь имеет полный доступ к тому или иному запросу
    def get_queryset(self):
        user = self.request.user
        return Todo.objects.filter(user=user).order_by('-created')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class TodoRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Todo.objects.filter(user=self.request.user)


class TodoToggleComplete(generics.UpdateAPIView):
    serializer_class = TodoToggleCompleteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Todo.objects.filter(user=self.request.user)

    def perform_update(self, serializer):
        serializer.instance.completed = not serializer.instance.completed
        # serializer.save(user=self.request.user) --> for mark who completed task
        serializer.save()


@csrf_exempt
def signup(request):
    if request.method == "POST":
        try:
            data = JSONParser().parse(request)  # data is dictionary
            user = User.objects.create_user(username=data['username'], password=data['password'])
            user.save()
            token = Token.objects.create(user=user)
            return JsonResponse({'token': str(token)}, status=201)
        except IntegrityError:
            return JsonResponse({'error': 'username taken. choose another username'}, status=400)


@csrf_exempt
def login(request):
    user = None
    if request.method == "POST":
        data = JSONParser().parse(request)
        user = authenticate(request, username=data['username'], password=data['password'])
    if user is None:
        return JsonResponse({'error': 'unable to login. checl username or password'}, status=400)
    else:  # возвращаем токен пользователя
        try:
            token = Token.objects.get(user=user)
        except:  # Если токена не существует в действующей базе данных, то создаём новый токен
            token = Token.objects.create(user=user)
        return JsonResponse({'token': str(token)}, status=201)
