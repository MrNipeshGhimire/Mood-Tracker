from rest_framework import serializers
from django.contrib.auth.models import User
from .models import MoodEntry, JournalEntry,Post,Comment,ReportSettings,Notification,ReportReminder
from django.utils.timezone import now

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email','first_name','last_name']


class MoodEntrySerializer(serializers.ModelSerializer):
    # Add a username field that gets the username from the related user model
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = MoodEntry
        fields = ['id', 'mood_description', 'date','user', 'username']  # Only include 'username' instead of 'user' 

class JournalEntrySerializer(serializers.ModelSerializer):
    # Include username from the related User model
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = JournalEntry
        fields = ['id', 'journal_description', 'date','user', 'username']  # Add any other fields you want to include
        

class CommentSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    class Meta:
        model = Comment
        fields = ['id', 'post', 'user','username', 'content', 'created_at']
        read_only_fields = ['created_at']
        
        
class PostSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ["id", "user", "content", "created_at", "comments"]


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'      
        
#================password reset serializers================#
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=3)
    

class ReportSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportSettings
        fields = ['user', 'report_time']  # You can include other fields if needed

    def validate_report_time(self, value):
        # Optionally, you can add validation for the report_time field
        if value <= now():
            raise serializers.ValidationError("The report generation time must be in the future.")
        return value
    



        

class ReportReminderSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportReminder
        fields = '__all__'