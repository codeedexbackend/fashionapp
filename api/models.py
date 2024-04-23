from django.db import models
from django.contrib.auth.models import  Group, Permission,BaseUserManager,AbstractBaseUser,PermissionsMixin
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class PasswordResetUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    otp_secret_key = models.CharField(max_length=32, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    groups = models.ManyToManyField(Group, related_name='passwordresetuser_set', blank=True, verbose_name=_('groups'))
    user_permissions = models.ManyToManyField(Permission, related_name='passwordresetuser_set', blank=True, verbose_name=_('user permissions'))

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=200,null=False)
    password2 = models.CharField(max_length=200,null=False, default='********')
    mobile = models.IntegerField(null=True, unique=True)
    otp = models.CharField(max_length=32, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    username = models.CharField(max_length=200, unique=True, null=True)
    name = models.CharField(max_length=200,null=True)
    groups = models.ManyToManyField(Group, related_name='user_set', blank=True, verbose_name=_('groups'))
    user_permissions = models.ManyToManyField(Permission, related_name='user_set', blank=True, verbose_name=_('user permissions'))
    otp_secret_key = models.CharField(max_length=32, blank=True, null=True)
    address1 = models.CharField(max_length=250, null=True, blank=True)
    address2 = models.CharField(max_length=250, null=True, blank=True)
    city = models.CharField(max_length=30, null=True, blank=True)
    state = models.CharField(max_length=20, null=True, blank=True)
    pincode = models.IntegerField( null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []





class Products(models.Model):
    Product_Name = models.CharField(max_length=100,null=False)
    Description = models.CharField(max_length=100,null=False)
    Product_Image1 = models.ImageField(upload_to="product_images", null=False)
    Product_Image2 = models.ImageField(upload_to="product_images", null=True)
    Product_Image3 = models.ImageField(upload_to="product_images", null=True)
    Product_Image4 = models.ImageField(upload_to="product_images", null=True)
    Product_Image5 = models.ImageField(upload_to="product_images", null=True)

    GENDER_CHOICES = [
        ('men', 'Men'),
        ('women', 'Women'),
        ('boy', 'Boy'),
        ('girl', 'Girl'),
    ]
    Gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=False)
    
    CATEGORY_CHOICES = [
        ('shirts', 'Shirts'),
        ('pants', 'Pants'),
        ('shoes', 'Shoes'),
        ('accessories', 'Accessories'),
    ]
    Category = models.CharField(max_length=20, choices=CATEGORY_CHOICES,null=False)

    Price = models.DecimalField(max_digits=10, decimal_places=2, null=False, validators=[MinValueValidator(0)])
    Offer_Price = models.DecimalField(max_digits=10, decimal_places=2, null=False)


    
    Size1 = models.CharField(max_length=10, null=False, default='')
    Size2 = models.CharField(max_length=10, null=False, default='')
    Size3 = models.CharField(max_length=10, null=False, default='')
    Size4 = models.CharField(max_length=10, null=False, default='')
    Size5 = models.CharField(max_length=10, null=False, default='')

 

    COLOR_CHOICES = [
        ('red', 'Red'),
        ('blue', 'Blue'),
        ('green', 'Green'),
        ('yellow', 'Yellow'),
    ]

    Color = models.CharField(max_length=20, choices=COLOR_CHOICES,null=False)

    def _str_(self):
        return self.Product_Name
    

class Wishlist(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    
    def __str__(self):
        return f'{self.user.username} - {self.product.Product_Name}'

    @property
    def product_name(self):
        return self.product.Product_Name

    @property
    def product_image(self):
        return self.product.Product_Image.url
    
class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    size = models.CharField(max_length=50)
    quantity = models.PositiveIntegerField(default=1)

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    payment_method = models.CharField(max_length=100, choices=[('COD', 'Cash on Delivery'), ('Online', 'Online Payment')])
    product_ids = models.CharField(max_length=255,null=True)
    product_names = models.CharField(max_length=255,null=True)
    total_price = models.FloatField(default=0.00)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id}"

    
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    product_name = models.CharField(max_length=100)
    product_image1 = models.ImageField(upload_to='product_images/')
    offer_price = models.FloatField(null=True)  # Allow null values
    quantity = models.PositiveIntegerField(default=1)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.product_name} - Quantity: {self.quantity} - Total: {self.total_price}"


class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE)  # Assuming you have a Product model
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review by {self.user.username} for {self.product.name}"