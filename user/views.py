from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate, get_user_model

from .serializers import (
    UserSerializer,
    AdminCreateSerializer,
    AdminUpdateSerializer,
    AdminListSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    UserProfileSerializer
)
from .permissions import IsSuperUser, IsAdminOrSuperUser

User = get_user_model()


class LoginView(APIView):
    """
    API endpoint for user login.
    Returns JWT tokens on successful authentication.
    Only active users with ADMIN or SUPERUSER role can login.
    """
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Authenticate user
        user = authenticate(email=email, password=password)
        
        if user is None:
            return Response(
                {'error': 'Invalid email or password'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if user is active
        if not user.is_active:
            return Response(
                {'error': 'User account is disabled'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if user has admin privileges
        if user.role not in [User.Role.ADMIN, User.Role.SUPERUSER]:
            return Response(
                {'error': 'You do not have permission to access this system'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user, context={'request': request}).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    API endpoint for user logout.
    Blacklists the refresh token.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response(
                    {'error': 'Refresh token is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(
                {'message': 'Logout successful'},
                status=status.HTTP_200_OK
            )

        except TokenError as e:
            return Response(
                {'error': f'Token error: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Invalid token: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )


class AdminCreateView(generics.CreateAPIView):
    """
    API endpoint for creating new admin users.
    Only accessible by superuser.
    """
    queryset = User.objects.filter(role=User.Role.ADMIN)
    serializer_class = AdminCreateSerializer
    permission_classes = [IsAuthenticated, IsSuperUser]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        return Response(
            {
                'message': 'Admin user created successfully',
                'user': UserSerializer(user, context={'request': request}).data
            },
            status=status.HTTP_201_CREATED
        )


class AdminListView(generics.ListAPIView):
    """
    API endpoint to list all admin users.
    Only accessible by admin and superuser.
    """
    serializer_class = AdminListSerializer
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    
    def get_queryset(self):
        """
        Return all active admin users (both ADMIN and SUPERUSER roles).
        """
        return User.objects.filter(
            role__in=[User.Role.ADMIN, User.Role.SUPERUSER],
            is_active=True
        ).order_by('-date_joined')


class AdminDetailView(generics.RetrieveAPIView):
    """
    API endpoint to retrieve a specific admin user.
    Only accessible by admin and superuser.
    """
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminOrSuperUser]
    
    def get_queryset(self):
        return User.objects.filter(role__in=[User.Role.ADMIN, User.Role.SUPERUSER])


class AdminUpdateView(generics.UpdateAPIView):
    """
    API endpoint to update a specific admin user.
    Only accessible by superuser.
    """
    serializer_class = AdminUpdateSerializer
    permission_classes = [IsAuthenticated, IsSuperUser]
    
    def get_queryset(self):
        return User.objects.filter(role=User.Role.ADMIN)
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response(
            {
                'message': 'Admin user updated successfully',
                'user': UserSerializer(instance, context={'request': request}).data
            },
            status=status.HTTP_200_OK
        )


class AdminDeleteView(generics.DestroyAPIView):
    """
    API endpoint to deactivate/delete a specific admin user.
    Only accessible by superuser.
    Performs soft delete by setting is_active to False.
    """
    queryset = User.objects.filter(role=User.Role.ADMIN)
    permission_classes = [IsAuthenticated, IsSuperUser]
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Prevent deactivating yourself
        if instance.id == request.user.id:
            return Response(
                {'error': 'You cannot deactivate your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Soft delete - deactivate user instead of deleting
        instance.is_active = False
        instance.save()
        
        return Response(
            {'message': 'Admin user deactivated successfully'},
            status=status.HTTP_200_OK
        )


class CurrentUserView(APIView):
    """
    API endpoint to get current logged-in user information.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    """
    API endpoint for changing user password.
    User must provide old password to change to new password.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        # Change password
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        # 🔒 Invalidate all refresh tokens for this user
        try:
            tokens = RefreshToken.for_user(user)
            tokens.blacklist()
        except Exception:
            pass  # Token may already be invalid
        
        return Response(
            {'message': "Password changed successfully. Please log in again."},
            status=status.HTTP_200_OK
        )


class UpdateProfileView(generics.UpdateAPIView):
    """
    API endpoint for users to update their own profile.
    Cannot change role or admin privileges.
    """
    serializer_class = AdminUpdateSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        # Remove is_active from data to prevent users from changing their own status
        data = request.data.copy()
        
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response(
            {
                'message': 'Profile updated successfully',
                'user': UserProfileSerializer(instance).data
            },
            status=status.HTTP_200_OK
        )