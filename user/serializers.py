from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for displaying user information.
    """
    
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'full_name',
            'contact_number',
            'image',
            'is_admin',
            'is_active',
            'date_joined'
        ]
        read_only_fields = ['id', 'date_joined']


class AdminCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new admin users.
    Only existing admins can use this.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = [
            'email',
            'full_name',
            'contact_number',
            'image',
            'password',
            'password_confirm'
        ]
    
    def validate(self, attrs):
        """
        Check that the two password fields match.
        """
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                "password": "Password fields didn't match."
            })
        return attrs
    
    def create(self, validated_data):
        """
        Create a new admin user.
        """
        # Remove password_confirm as it's not needed for user creation
        validated_data.pop('password_confirm')
        
        # Create user with admin privileges
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            full_name=validated_data['full_name'],
            contact_number=validated_data.get('contact_number', ''),
            image=validated_data.get('image', None),
            is_admin=True,
            is_staff=True,
            is_active=True
        )
        
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )