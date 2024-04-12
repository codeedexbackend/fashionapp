from rest_framework import serializers
from .models import User,Products,Wishlist,Cart,Order,Review
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser



class UserProfileSerializer(serializers.ModelSerializer):
    mobile = serializers.CharField(write_only=True, required=True) 
    password = serializers.CharField(write_only=True, required=True)  # Add required=True
    password2 = serializers.CharField(write_only=True, required=True)  # Add required=True
    name = serializers.CharField(write_only=True, required=True)  # Add required=True

    class Meta:
        model = User
        fields = ['email', 'password', 'password2', 'mobile','name']

    def validate(self, data):
        # Check if password and password2 match
        if data.get('password') != data.get('password2'):
            raise serializers.ValidationError({'password': 'Passwords do not match'})

        return data

    def create(self, validated_data):
        # Pop password2 as we don't need it when creating the user
        password2 = validated_data.pop('password2', None)
        # Create user instance without saving it yet
        user = User(**validated_data)
        # Set password using set_password method
        user.set_password(validated_data['password'])
        # Save the user
        user.save()
        return user

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
    
class UserViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','email', 'mobile', 'username', 'address1', 'address2', 'city', 'state', 'pincode']



class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


#password_reset
User = get_user_model()

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()



class PassOTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=4)

class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')

        if new_password != confirm_new_password:
            raise serializers.ValidationError("New password and confirm new password do not match.")
        
        return data

class ProductSerializer(serializers.ModelSerializer):
    product_images = serializers.ListField(child=serializers.ImageField(), write_only=True)
    sizes = serializers.CharField(write_only=True)
    is_wishlisted = serializers.SerializerMethodField()

    class Meta:
        model = Products
        fields = ['id','Product_Name', 'Description', 'product_images', 'sizes', 'Gender', 'Category', 'Price', 'Offer_Price', 'Color', 'is_wishlisted']

    def get_is_wishlisted(self, instance):
        wishlist_products = self.context.get('wishlist_products', [])
        return instance.id in wishlist_products

    
    def create(self, validated_data):
        product_images = validated_data.pop('product_images', [])
        sizes = validated_data.pop('sizes', '').split(',')[:5]  # Split sizes by comma and take only the first 5

        product = Products.objects.create(**validated_data)

        # Assign images to product_image fields
        for i, image in enumerate(product_images):
            setattr(product, f'Product_Image{i + 1}', image)

        # Assign sizes to Size fields
        for i, size in enumerate(sizes):
            setattr(product, f'Size{i + 1}', size)

        product.save()

        return product

    def get_product_images(self, obj):
        return [getattr(obj, f'Product_Image{i}') for i in range(1, 6)]

    def get_sizes(self, obj):
        return [getattr(obj, f'Size{i}') for i in range(1, 6)]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['product_images'] = [self.context['request'].build_absolute_uri(image.url) for image in self.get_product_images(instance) if image]
        representation['sizes'] = [size for size in self.get_sizes(instance) if size]
        return representation
    

class CartSerializer(serializers.ModelSerializer):
    product_images = serializers.SerializerMethodField()
    product_id = serializers.SerializerMethodField()
    product_name = serializers.SerializerMethodField()
    selected_size = serializers.SerializerMethodField()
    price = serializers.SerializerMethodField()
    total_price = serializers.SerializerMethodField()

    class Meta:
        model = Cart
        fields = ['id','product_id', 'user_id', 'product_name', 'quantity', 'product_images', 'selected_size', 'price', 'total_price']

    def get_product_images(self, instance):
        request = self.context.get('request')
        if request:
            product = instance.product
            product_images = []
            for i in range(1, 6):
                image_attr = getattr(product, f'Product_Image{i}')
                if image_attr:
                    product_images.append(request.build_absolute_uri(image_attr.url))
            return product_images
        return None

    def get_selected_size(self, instance):
        return instance.size 
    
    def get_product_id(self, instance):
        return instance.product.id 

    def get_product_name(self, instance):
        return instance.product.Product_Name

    def get_price(self, instance):
        return instance.product.Offer_Price

    def get_total_price(self, instance):
        return instance.product.Offer_Price * instance.quantity


class WishlistSerializer(serializers.ModelSerializer):
    product_name = serializers.SerializerMethodField()
    product_image = serializers.SerializerMethodField()
    is_wishlisted = serializers.SerializerMethodField()

    class Meta:
        model = Wishlist
        fields = ['id', 'user', 'product', 'product_name', 'product_image', 'is_wishlisted']

    def get_is_wishlisted(self, instance):
        wishlist_products = self.context.get('wishlist_products', [])
        product_id = instance.product_id
        print("wishlist_products:", wishlist_products)
        print("product_id:", product_id)
        return product_id in wishlist_products


    def get_product_name(self, obj):
        return obj.product.Product_Name

    def get_product_image(self, obj):
        # Assuming Product model has fields Product_Image1, Product_Image2, etc.
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(obj.product.Product_Image1.url)  # Change this according to your model
        return ''


class CheckoutSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    products = serializers.ListField(child=serializers.IntegerField())
    quantities = serializers.ListField(child=serializers.IntegerField())


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'


class CategoryFilterSerializer(serializers.Serializer):
    category = serializers.CharField()

    def get_is_wishlisted(self, instance):
        wishlist_products = self.context.get('wishlist_products', [])
        return instance.id in wishlist_products



class GenderFilterSerializer(serializers.Serializer):
    gender = serializers.ChoiceField(choices=Products.GENDER_CHOICES, required=False)

    def get_is_wishlisted(self, instance):
        wishlist_products = self.context.get('wishlist_products', [])
        return instance.id in wishlist_products

    def validate_gender(self, value):
        # Validate the gender field here if needed
        return value

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['id', 'user', 'product', 'rating', 'comment', 'created_at']


class ProductSearchSerializer(serializers.Serializer):
    search_query = serializers.CharField(max_length=100, required=True)