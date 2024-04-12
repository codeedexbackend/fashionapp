from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from .serializers import UserProfileSerializer,VerifyOTPSerializer,PasswordResetSerializer,PassOTPVerificationSerializer,ChangePasswordSerializer,UserViewSerializer,UserProfileUpdateSerializer,\
ProductSerializer,CartSerializer,WishlistSerializer,CheckoutSerializer,OrderSerializer,CategoryFilterSerializer,GenderFilterSerializer,ReviewSerializer,\
ProductSearchSerializer
from .models import Products,Wishlist,Cart,Order,Review
import random
import jwt
import datetime
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import ValidationError
from rest_framework.exceptions import NotFound
from rest_framework.generics import RetrieveUpdateAPIView
from django.core.paginator import Paginator, EmptyPage
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from django.db import transaction







def generate_otp():
    return str(random.randint(1000, 9999))

User = get_user_model()
#user_registration

def send_otp_email(email, otp):
    subject = 'Your OTP for Registration'
    message = f'Your OTP is: {otp}'
    from_email = 'praveen.codeedex@gmail.com' 
    send_mail(subject, message, from_email, [email])

@api_view(['POST'])
def register(request):
    serializer = UserProfileSerializer(data=request.data)

    if serializer.is_valid():
        email = serializer.validated_data['email']

        if User.objects.filter(email=email).exists():
            return Response({'message': 'Email already registered', 'status': False}, status=status.HTTP_400_BAD_REQUEST)

        otp = ''.join([str(random.randint(0, 9)) for _ in range(4)])

        user = serializer.save(otp=otp)

        send_otp_email(email, otp)

        return Response({'message': 'OTP sent to email', 'status': True}, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
def verify(request):
    serializer = VerifyOTPSerializer(data=request.data)

    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp_entered = serializer.validated_data['otp']

        try:
            user_profile = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'Email not registered','status':False}, status=status.HTTP_400_BAD_REQUEST)

        if user_profile.otp == otp_entered:
            user_profile.otp = None
            user_profile.save()
            return Response({'message': 'OTP verified successfully','status':True}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid OTP','status':False}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
 #user_login
   
class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            raise ValidationError('Email and password are required.', code='missing_credentials')

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!', False)

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!', False)

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'id': user.id,
            'token': token,
            'message': 'Login successful',
            'status': True
        }
        return response
class UserView(APIView):
    def get(self, request, user_id):
        user = User.objects.filter(id=user_id).first()

        if not user:
            raise NotFound('User not found!')

        serializer = UserViewSerializer(user)
        return Response({
            'user_data': serializer.data,
            'message': 'User Profile View',
            'status': True
        })
    
class UserProfileEditView(RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileUpdateSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response({
            'message': 'Profile updated successfully',
            'status': True,
            'user_data': serializer.data
        })

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = queryset.filter(id=self.kwargs.get('pk')).first()
        if not obj:
            raise NotFound('User not found!')
        return obj

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout successful',
            'status': True
        }
        return response
    
#password_reset
User = get_user_model()

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        email = request.data.get('email', None)
        user = User.objects.filter(email=email).first()

        if user:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(4)])

            user.otp_secret_key = otp
            user.save()

            email_subject = 'Password Reset OTP'
            email_body = f'Your OTP for password reset is: {otp}'
            to_email = [user.email] 
            send_mail(email_subject, email_body, from_email=None, recipient_list=to_email)


            return Response({'detail': 'OTP sent successfully.','status':True}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'User not found.','status':False}, status=status.HTTP_404_NOT_FOUND)
        
User = get_user_model()

class PassOTPVerificationView(generics.GenericAPIView):
    serializer_class = PassOTPVerificationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email', None)
        otp = serializer.validated_data.get('otp', None)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)

        if not self.verify_otp(user.otp_secret_key, otp):
            return Response({'detail': 'Invalid OTP.', 'status': False}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_secret_key = None
        user.save()

        return Response({'detail': 'OTP verification successful. Proceed to reset password.', 'status': True}, status=status.HTTP_200_OK)

    def verify_otp(self, secret_key, otp):

        return secret_key == otp



class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        new_password = serializer.validated_data.get('new_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        return Response({'detail': 'Password changed successfully.', 'status': True}, status=status.HTTP_200_OK)


class ProductCreateAPIView(generics.CreateAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer


class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

    def paginate_queryset(self, queryset, request, view=None):
        page_size = self.get_page_size(request)
        if not page_size:
            return None

        self.page_size = page_size
        return super().paginate_queryset(queryset, request, view)
    
class ProductsListView(APIView):
    pagination_class = CustomPageNumberPagination

    def get(self, request):
        products = Products.objects.all()
        paginator = Paginator(products, self.pagination_class.page_size)
        page_number = request.query_params.get('page')
        try:
            page = paginator.page(page_number)
        except EmptyPage:
            return Response({'products': [], 'next': None, 'previous': None})

        # Get the current user's wishlist items

        paginator = self.pagination_class()
        paginated_products = paginator.paginate_queryset(products, request)

        # Serialize the paginated products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})

        # Return paginated response
        return paginator.get_paginated_response(serializer.data)

class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10  # Set the page size according to your requirements
    page_size_query_param = 'page_size'  # Optional: customize the query parameter for page size
    max_page_size = 1000  # Optional: set the maximum page size

# In your UserProductsListView:
class UserProductsListView(APIView):
    pagination_class = CustomPageNumberPagination

    def get(self, request, user_id):
        # Retrieve all products
        products = Products.objects.all()

        # Get the user's wishlist items
        wishlist_products = Wishlist.objects.filter(user_id=user_id).values_list('product_id', flat=True)

        # Paginate the products
        paginator = self.pagination_class()
        paginated_products = paginator.paginate_queryset(products, request)

        # Serialize the paginated products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request, 'wishlist_products': wishlist_products})

        # Return paginated response
        return paginator.get_paginated_response(serializer.data)

    

class ProductDetailView(generics.RetrieveAPIView):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer
    # permission_classes = [IsAuthenticated]


class ProductUserSingleView(APIView):
    def get(self, request, user_id, product_id):
        try:
            # Retrieve the product associated with the given product ID
            product = Products.objects.get(id=product_id)
        except Products.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Get the user's wishlist items
        wishlist_products = Wishlist.objects.filter(user_id=user_id).values_list('product_id', flat=True)

        # Serialize the product
        serializer = ProductSerializer(product, context={'request': request, 'wishlist_products': wishlist_products})

        return Response(serializer.data)




class AddToCartView(APIView):
    def post(self, request, user_id, product_id, size):
        # Get the user and product objects
        user = get_object_or_404(User, pk=user_id)
        product = get_object_or_404(Products, pk=product_id)

        # Create or update the cart item
        cart_item, created = Cart.objects.get_or_create(user=user, product=product, size=size)

        # Update the quantity
        if not created:
            cart_item.quantity += 1
            cart_item.save()

        # Pass request object to serializer context
        serializer = CartSerializer(cart_item, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    

class UserCartView(APIView):
    def get(self, request, user_id):
        # Retrieve the cart items of the user
        cart_items = Cart.objects.filter(user_id=user_id)

        # Calculate the total price for each cart item and the total cart price
        total_cart_price = 0
        for cart_item in cart_items:
            cart_item.total_price = cart_item.quantity * cart_item.product.Offer_Price
            total_cart_price += cart_item.total_price

        # Serialize the cart items with the total price
        serializer = CartSerializer(cart_items, context={'request': request}, many=True)

        # Add the total cart price to the response data
        response_data = {
            'message': 'Products Retrieved Successfully',
            'cart_items': serializer.data,
            'total_cart_price': total_cart_price
        }

        return Response(response_data, status=status.HTTP_200_OK)
    
class UpdateCartView(APIView):
    def put(self, request, user_id, cart_item_id):
        cart_item = get_object_or_404(Cart, pk=cart_item_id, user_id=user_id)
        serializer = CartSerializer(cart_item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            response_data = {
            'message': 'Updated Cart Successfully',
            'status':True
        }

            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteCartItemView(APIView):
    def delete(self, request, user_id, cart_item_id):
        cart_item = get_object_or_404(Cart, pk=cart_item_id, user_id=user_id)
        cart_item.delete()
        cart_items = Cart.objects.filter(user_id=user_id)

        # Serialize the cart items with their associated product images

        response_data = {
            'message': 'Removed From Cart Successfully',
            'status':True
        }

        return Response(response_data, status=status.HTTP_200_OK)
    
class AddToWishlistView(APIView):
    def post(self, request, user_id, product_id):
        user = get_object_or_404(User, pk=user_id)
        product = get_object_or_404(Products, pk=product_id)
        wishlist_item, created = Wishlist.objects.get_or_create(user=user, product=product)
        if created:
            return Response({'message': 'Product added to wishlist successfully','status':True}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Product already exists in wishlist','status':False}, status=status.HTTP_200_OK)

class RemoveFromWishlistView(APIView):
    def delete(self, request, user_id, product_id):
        user = get_object_or_404(User, pk=user_id)
        product = get_object_or_404(Products, pk=product_id)
        wishlist_item = get_object_or_404(Wishlist, user=user, product=product)
        wishlist_item.delete()
        return Response({'message': 'Product removed from wishlist successfully','status':True}, status=status.HTTP_200_OK)

class WishlistPagination(PageNumberPagination):
    page_size = 10  # Number of items per page
    page_size_query_param = 'page_size'  # Parameter to control the page size
    max_page_size = 100  # Maximum page size

class ViewWishlistView(APIView):
    pagination_class = WishlistPagination

    def get(self, request, user_id):
        user = get_object_or_404(User, pk=user_id)
        wishlist_items = Wishlist.objects.filter(user=user)

        # Extract product IDs from wishlist_items
        wishlist_products = list(wishlist_items.values_list('product_id', flat=True))

        # Paginate the queryset
        paginator = Paginator(wishlist_items, self.pagination_class.page_size)
        page_number = request.query_params.get('page')
        try:
            page = paginator.page(page_number)
        except EmptyPage:
            return Response({'wishlist_items': [], 'next': None, 'previous': None})

        serializer = WishlistSerializer(
            page, 
            many=True, 
            context={'request': request, 'wishlist_products': wishlist_products}  # Pass only product IDs
        )
        return Response({
            'wishlist_items': serializer.data,
            'next': page.next_page_number() if page.has_next() else None,
            'previous': page.previous_page_number() if page.has_previous() else None
        })

class CheckoutView(APIView):
    def post(self, request, user_id, cart_id):
        try:
            with transaction.atomic():
                total_price = 0
                cart_items = Cart.objects.filter(user_id=user_id, id=cart_id)

                if not cart_items.exists():
                    return Response({'error': 'Cart not found'}, status=status.HTTP_404_NOT_FOUND)

                # Calculate total price and delete cart items
                for cart_item in cart_items:
                    product = cart_item.product
                    total_price += product.Offer_Price * cart_item.quantity
                    cart_item.delete()

                # Create order or record checkout information
                # For simplicity, just return the total price
                return Response({'message': 'Checkout successful', 'total_price': total_price}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OrderListView(ListAPIView):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_id = self.kwargs.get('user_id')
        return Order.objects.filter(user_id=user_id)
    



class CustomPageNumberPagination(PageNumberPagination):
    def get_next_page_number(self):
        if not self.page.has_next():
            return None
        return self.page.next_page_number()

    def get_previous_page_number(self):
        if not self.page.has_previous():
            return None
        return self.page.previous_page_number()

class CategoryFilterView(APIView):
    def get(self, request):
        serializer = CategoryFilterSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        category = serializer.validated_data['category']
        
        # Filter products by category
        products = Products.objects.filter(Category=category)
        
        # Pagination
        paginator = CustomPageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        
        # Serialize the filtered products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})
        
        # Get wishlist items for the current user
        user = request.user
        if not user.is_authenticated:
            # If user is not authenticated, set wishlist_items to an empty queryset
            wishlist_items = Wishlist.objects.none()
        else:
            wishlist_items = Wishlist.objects.filter(user=user)
        
        # Get a set of product IDs that are wishlisted by the user
        wishlisted_products = set(wishlist_items.values_list('product__id', flat=True))
        
        # Iterate through the serialized products and add a field to indicate whether each product is wishlisted or not
        for product_data in serializer.data:
            product_id = product_data['id']
            product_data['is_wishlisted'] = product_id in wishlisted_products
        
        response = paginator.get_paginated_response(serializer.data)
        response.data['next_page'] = paginator.get_next_page_number()
        response.data['previous_page'] = paginator.get_previous_page_number()
        
        return response
    
class GenderFilterView(APIView):
    def get(self, request):
        serializer = GenderFilterSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        gender = serializer.validated_data['gender']
        
        # Filter products by category
        products = Products.objects.filter(Gender=gender)
        
        # Pagination
        paginator = CustomPageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        
        # Serialize the filtered products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})
        
        # Get wishlist items for the current user
        user = request.user
        if not user.is_authenticated:
            # If user is not authenticated, set wishlist_items to an empty queryset
            wishlist_items = Wishlist.objects.none()
        else:
            wishlist_items = Wishlist.objects.filter(user=user)
        
        # Get a set of product IDs that are wishlisted by the user
        wishlisted_products = set(wishlist_items.values_list('product__id', flat=True))
        
        # Iterate through the serialized products and add a field to indicate whether each product is wishlisted or not
        for product_data in serializer.data:
            product_id = product_data['id']
            product_data['is_wishlisted'] = product_id in wishlisted_products
        
        response = paginator.get_paginated_response(serializer.data)
        response.data['next_page'] = paginator.get_next_page_number()
        response.data['previous_page'] = paginator.get_previous_page_number()
        
        return response
    
class UserCategoryFilterView(APIView):
    def get(self, request, user_id):
        serializer = CategoryFilterSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        category = serializer.validated_data['category']
        
        # Filter products by category
        products = Products.objects.filter(Category=category)
        
        # Pagination
        paginator = CustomPageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        
        # Serialize the filtered products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})
        
        # Get wishlist items for the specified user
        # user = get_object_or_404(User, pk=user_id)
        # wishlist_items = Wishlist.objects.filter(user=user)
        
        # # Get a set of product IDs that are wishlisted by the user
        # wishlisted_products = set(wishlist_items.values_list('product__id', flat=True))
        wishlisted_products = Wishlist.objects.filter(user_id=user_id).values_list('product_id', flat=True)

        
        # Iterate through the serialized products and add a field to indicate whether each product is wishlisted or not
        for product_data in serializer.data:
            product_id = product_data['id']
            product_data['is_wishlisted'] = product_id in wishlisted_products
        
        response = paginator.get_paginated_response(serializer.data)
        response.data['next_page'] = response.data['next']
        response.data['previous_page'] = response.data['previous']
        del response.data['next']
        del response.data['previous']
        
        return response
    
class UserGenderFilterView(APIView):
    def get(self, request, user_id):
        serializer = GenderFilterSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        gender = serializer.validated_data['gender']
        
        # Filter products by gender
        products = Products.objects.filter(Gender=gender)
        
        # Pagination
        paginator = CustomPageNumberPagination()
        paginated_products = paginator.paginate_queryset(products, request)
        
        # Serialize the filtered products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})
        
        # Get wishlist items for the specified user
        # user = get_object_or_404(User, pk=user_id)
        # wishlist_items = Wishlist.objects.filter(user=user)
        
        # Get a set of product IDs that are wishlisted by the user
        wishlisted_products = Wishlist.objects.filter(user_id=user_id).values_list('product_id', flat=True)
        # wishlisted_products = set(wishlist_items.values_list('product__id', flat=True))
        
        # Iterate through the serialized products and add a field to indicate whether each product is wishlisted or not
        for product_data in serializer.data:
            product_id = product_data['id']
            product_data['is_wishlisted'] = product_id in wishlisted_products
        
        response = paginator.get_paginated_response(serializer.data)
        response.data['next_page'] = response.data['next']
        response.data['previous_page'] = response.data['previous']
        del response.data['next']
        del response.data['previous']
        
        return response


    
class AddReviewView(APIView):
    def post(self, request, user_id, product_id):
        # Create a mutable copy of the request data
        mutable_data = request.data.copy()
        
        # Add user_id and product_id to the mutable data
        mutable_data['user'] = user_id
        mutable_data['product'] = product_id

        # Serialize and save the review
        serializer = ReviewSerializer(data=mutable_data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Review added successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ProductReviewView(APIView):
    def get(self, request, product_id):
        # Retrieve reviews for the specified product
        reviews = Review.objects.filter(product_id=product_id)
        
        # Serialize the review data
        serializer = ReviewSerializer(reviews, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UpdateReviewView(APIView):
    def put(self, request, user_id, product_id):
        try:
            review = Review.objects.get(user=user_id, product=product_id)
        except Review.DoesNotExist:
            return Response({'error': 'Review does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = ReviewSerializer(review, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Review updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class ProductSearchPagination(PageNumberPagination):
    page_size = 10  # Set the number of items per page

class ProductSearchView(APIView):
    pagination_class = ProductSearchPagination

    def get(self, request):
        serializer = ProductSearchSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        search_query = serializer.validated_data['search_query']
        
        # Perform search by product name
        products = Products.objects.filter(Product_Name__icontains=search_query)
        
        # Paginate the filtered products
        paginator = self.pagination_class()
        paginated_products = paginator.paginate_queryset(products, request)
        
        # Serialize the paginated products
        serializer = ProductSerializer(paginated_products, many=True, context={'request': request})
        
        # Construct the response data with pagination metadata
        response_data = {
            'results': serializer.data,
            'count': paginator.page.paginator.count,
            'next_page': paginator.page.next_page_number() if paginator.page.has_next() else None,
            'previous_page': paginator.page.previous_page_number() if paginator.page.has_previous() else None,
        }
        
        return Response(response_data)