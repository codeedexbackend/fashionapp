from django.urls import path

from .import views



urlpatterns = [

    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify, name='verify'),
    path('login/',views.LoginView.as_view()),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('userprofile/<int:user_id>/', views.UserView.as_view(), name='user_profile'),
    path('userprofileedit/<int:pk>/', views.UserProfileEditView.as_view(), name='user_profile_edit_by_id'),

    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-otp/', views.PassOTPVerificationView.as_view(), name='otp-verification'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),

    path('add-products/', views.ProductCreateAPIView.as_view(), name='product-create'),
    path('view-products/', views.ProductsListView.as_view(), name='products-list'),
    path('single-product/<int:pk>/', views.ProductDetailView.as_view(), name='product-detail'),
    path('add-to-cart/<int:user_id>/<int:product_id>/<str:size>/', views.AddToCartView.as_view(), name='cart-add-product'),
    path('view-cart/<int:user_id>/', views.UserCartView.as_view(), name='user_cart'),
    path('update-cart/<int:user_id>/<int:cart_item_id>/', views.UpdateCartView.as_view(), name='update_cart'),
    path('delete-cart-item/<int:user_id>/<int:cart_item_id>/', views.DeleteCartItemView.as_view(), name='delete_cart_item'),
    path('products-category/', views.CategoryFilterView.as_view(), name='category-filter'),
    path('products-gender/', views.GenderFilterView.as_view(), name='gender_filter'),
    path('add-review/<int:user_id>/<int:product_id>/', views.AddReviewView.as_view(), name='add_review'),
    path('view-review/<int:product_id>/', views.ProductReviewView.as_view(), name='product_reviews'),
    path('update-review/<int:user_id>/<int:product_id>/', views.UpdateReviewView.as_view(), name='update_review'),
    path('search/', views.ProductSearchView.as_view(), name='product_search'),
    path('user-products/<int:user_id>/', views.UserProductsListView.as_view(), name='user-products-list'),
    path('user-singleproducts/<int:user_id>/<int:product_id>/', views.ProductUserSingleView.as_view(), name='user-product-detail'),
    path('category-filter/<int:user_id>/', views.UserCategoryFilterView.as_view(), name='category-filter'),
    path('gender-filter/<int:user_id>/', views.UserGenderFilterView.as_view(), name='gender-filter'),

    path('add-to-wishlist/<int:user_id>/<int:product_id>/', views.AddToWishlistView.as_view(), name='add_to_wishlist'),
    path('remove-from-wishlist/<int:user_id>/<int:product_id>/', views.RemoveFromWishlistView.as_view(), name='remove_from_wishlist'),
    path('view-wishlist/<int:user_id>/', views.ViewWishlistView.as_view(), name='view_wishlist'),

    path('checkout/<int:user_id>/<int:cart_id>/', views.CheckoutView.as_view(), name='checkout'),
    path('orders/<int:user_id>/', views.OrderListView.as_view(), name='user-order-list'),



]