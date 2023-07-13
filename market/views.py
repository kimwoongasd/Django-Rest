import jwt
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from django.http import Http404, HttpResponseRedirect
from rest_framework import status, status, viewsets
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework.decorators import APIView
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from .serializers import *
from blog.settings import SECRET_KEY
from blog.password import *
from .models import *

# 로그인
class Authview(APIView):
    # 로그인
    def post(self, request):
    	# 유저 인증
        user = authenticate(
            username = request.data.get("username"), email=request.data.get("email"), password=request.data.get("password")
        )
        # 이미 회원가입 된 유저일 때
        print(user)
        if user is not None:
            serializer = UserSerializer(user)
            # jwt 토큰 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "message": "login success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
            print(res)
            # jwt 토큰 => 쿠키에 저장
            response = HttpResponseRedirect("{% url 'home' %}")
            response.set_cookie("access", access_token, httponly=True)
            response.set_cookie("refresh", refresh_token, httponly=True)
            return response
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    # 로그아웃
    def delete(self, request):
        # 쿠키에 저장된 토큰 삭제 => 로그아웃 처리
        response = Response({
            "message": "Logout success"
            }, status=status.HTTP_202_ACCEPTED)
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        return response
    
class UserInfo(APIView):
    # 유저 정보 확인
    def get(self, request):
        try:
            print(request.COOKIES)
            # access token을 decode 해서 유저 id 추출 => 유저 식별
            access = request.COOKIES.get('access')
            refresh = request.COOKIES.get('refresh')
            try:
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            except:
                payload = jwt.decode(refresh, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(User, pk=pk)
            # print(user)
            serializer = UserSerializer(instance=user)
            # print(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except(jwt.exceptions.ExpiredSignatureError):
            # 토큰 만료 시 토큰 갱신
            data = {'refresh': request.COOKIES.get('refresh', None)}
            serializer = TokenRefreshSerializer(data=data)  # type: ignore
            if serializer.is_valid(raise_exception=True):
                access = serializer.data.get('access', None)
                refresh = serializer.data.get('refresh', None)
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])  # type: ignore
                pk = payload.get('user_id')
                user = get_object_or_404(User, pk=pk)
                serializer = UserSerializer(instance=user)
                res = Response(serializer.data, status=status.HTTP_200_OK)
                res.set_cookie('access', access)  # type: ignore
                res.set_cookie('refresh', refresh)  # type: ignore
                print(refresh)
                return res
            raise jwt.exceptions.InvalidTokenError

        except(jwt.exceptions.InvalidTokenError):
            # 사용 불가능한 토큰일 때
            return Response(status=status.HTTP_400_BAD_REQUEST)
    
class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # jwt 토큰 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "message": "register successs",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK,
            )
            
            # jwt 토큰 => 쿠키에 저장
            res.set_cookie("access", access_token, httponly=True)
            res.set_cookie("refresh", refresh_token, httponly=True)
            
            return res
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# jwt 토근 인증 확인용 뷰셋
# Header - Authorization : Bearer <발급받은토큰>
class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer

class PostPagination(PageNumberPagination):
    page_size = 10

class PostList(APIView):
    pagination_class = PostPagination
    
    # post list 보여줄 때
    def get(self, request):
        posts = Post.objects.order_by('-pk')
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(posts, request)
        serializer = PostSerializer(result_page, many=True)
        context = {"post_list" : serializer.data}
        return Response(context)
    
    
class PostCreateAPI(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author = request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PostDetail(APIView):
    def get_object(self, pk):
        try:
            return Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        post = self.get_object(pk)
        serializer = PostSerializer(post)
        return Response(serializer.data)
    
    def post(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(post=post)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk, format=None):
        post = self.get_object(pk)
        serializer = PostSerializer(post, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk, format=None):
        post = self.get_object(pk)
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CommentManageApi(APIView):
    def get_object(self, pk, comment_pk):
        try:
            return Comment.objects.filter(post=pk).get(pk=comment_pk)
        except Post.DoesNotExist:
            raise Http404
        
    def get(self, request, pk, comment_pk, form=None):
        comment = self.get_object(pk, comment_pk)
        serializer = CommentSerializer(comment)
        return Response(serializer.data)
    
    def post(self, request, pk, comment_pk, format=None):
        comment = self.get_object(pk, comment_pk)
        data = request.data.copy()
        data['comment'] = comment.id  # type: ignore 
        serializer = ReplySerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def put(self, request, pk, comment_pk, *args, **kwargs):
        comment = self.get_object(pk, comment_pk)
        serializer = CommentSerializer(comment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk, comment_pk, *args, **kwargs):
        comment = self.get_object(pk, comment_pk)
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ReplyManageApi(APIView):
    def get_object(self, pk, comment_pk, reply_pk):
        try:
            return Reply.objects.filter(comment__post=pk, comment_id=comment_pk).get(pk=reply_pk)
        except Post.DoesNotExist:
            raise Http404
        
    def get(self, request, pk, comment_pk, reply_pk, *args, **kwargs):
        reply = self.get_object(pk, comment_pk, reply_pk)
        serializer = ReplySerializer(reply)
        return Response(serializer.data)
    
    def put(self, request, pk, comment_pk, reply_pk, *args, **kwargs):
        reply = self.get_object(pk, comment_pk, reply_pk)
        serializer = ReplySerializer(reply, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, comment_pk, reply_pk, *args, **kwargs):
        reply = self.get_object(pk, comment_pk, reply_pk)
        reply.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

User = get_user_model()
class UpdateProfileApi(APIView):
    def get(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        serializer = ProfileSerializer(user.profile) # type: ignore
        return Response(serializer.data)
    
    def put(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        serializer = ProfileSerializer(user.profile, data=request.data) # type: ignore
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class CartManageAPI(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'market/cart.html'
    
    def get(self, request):
        user_id = request.user.id
        cart_items = Cart.objects.filter(user=user_id)
        serializer = CartSerializer(cart_items, many=True)
        cart_data = serializer.data
        items = []
        for item in cart_data:
            product_id = item['product']
            product = Post.objects.get(id=product_id)
            items.append({
                    "post_id": product_id,
                    "name" : product.title,
                    "price" : product.price,
                    "quantity" : item["quantity"],
                    "total" : product.price * item["quantity"],
                })
        content = {"cart_data" : cart_data, "option": items}
        return Response(content)
    
    def put(self, request):
        user_id = request.user.id
        cart_items = Cart.objects.filter(user=user_id)
        data = request.data
        data['user'] = user_id
        data['product'] = CartSerializer(cart_items.get(id=data['id'])).data['product']
        new_item = Cart.objects.get(id=data['id'])
        serializer = CartSerializer(new_item, data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    def delete(self, request):
        user_id = request.user.id
        cart_items = Cart.objects.filter(user=user_id)
        serializer = CartSerializer(cart_items, many=True)
        cart_data = serializer.data
        
        for item in cart_data:
            if item['cancle'] == True:
                print(item['id'])
                Cart.objects.get(id=item['id']).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CartCreatAPI(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        request.data['user'] = request.user.id
        serializer = CartSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    