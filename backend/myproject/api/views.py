from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout,update_session_auth_hash
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken 
from .serializers import UserSerializer, MoodEntrySerializer,JournalEntrySerializer,PostSerializer,CommentSerializer,PasswordResetRequestSerializer, VerifyOTPSerializer, ResetPasswordSerializer,ReportSettingsSerializer,NotificationSerializer,ReportReminderSerializer
from .models import MoodEntry, JournalEntry,Post,Comment,PasswordResetOTP,ChatMessage,ReportSettings,Notification,ReportReminder,Reminder
import openai
from openai import OpenAIError  # Correct import
from django.utils.timezone import localtime
from django.conf import settings
from datetime import datetime, timedelta
from django.utils.timezone import now
from io import BytesIO
from django.http import FileResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Table, TableStyle
import os


from django.utils.timezone import now


from django.contrib.auth.hashers import make_password,check_password
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
import json
from django.middleware.csrf import get_token
from django.core.mail import send_mail
from rest_framework.views import APIView
import random

from dotenv import load_dotenv

load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")
# openai.api_key = "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"

# Generate JWT tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# User registration
@api_view(['POST'])
def register_user(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)
    return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)

# User login
@api_view(['POST'])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)   #session generate garxa
        print(request.user)
        tokens = get_tokens_for_user(user)
        return Response({'tokens': tokens, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
#@permission_classes([IsAuthenticated])
def logout_user(request):
    logout(request)  # Ends the user's session
    return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)

# Get authenticated user profile
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)




    

@api_view(['POST', 'GET'])
def mood_entries(request):
    """Handles creating and retrieving mood entries for the user specified by user_id."""
    
    user_id = request.data.get('user')  # Get the user ID from the request data

    if not user_id:
        return Response({'message': 'User ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)  # Fetch the user object using user_id
    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'POST':
        mood_description = request.data.get('mood_description')

        if not mood_description:
            return Response({'message': 'Mood description is required.'}, status=status.HTTP_400_BAD_REQUEST)

        mood_entry = MoodEntry.objects.create(
            mood_description=mood_description,
            user=user
        )
        mood_entry.save()

        return Response({'message': 'Mood added successfully'}, status=status.HTTP_201_CREATED)

    elif request.method == 'GET':
        mood_entries = MoodEntry.objects.filter(user=user).order_by('-date')
        serializer = MoodEntrySerializer(mood_entries, many=True)

        return Response({'mood_entries': serializer.data}, status=status.HTTP_200_OK)


@api_view(['GET', 'PUT', 'DELETE'])
def mood_entries_detail(request, mood_id):
    """Handles retrieving, updating, and deleting a specific mood entry."""
    user = request.user  # Get the authenticated user

    mood_entry = get_object_or_404(MoodEntry, id=mood_id, user=user)

    if request.method == 'GET':
        serializer = MoodEntrySerializer(mood_entry)
        return Response({'mood_entry': serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        mood_description = request.data.get('mood_description')

        if not mood_description:
            return Response({'message': 'Mood description is required.'}, status=status.HTTP_400_BAD_REQUEST)

        mood_entry.mood_description = mood_description
        mood_entry.save()

        serializer = MoodEntrySerializer(mood_entry)
        return Response({
            'message': 'Mood entry updated successfully.',
            'updated_mood_entry': serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'DELETE':
        mood_entry.delete()
        return Response({'message': 'Mood entry deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)





# @api_view(['POST', 'GET'])
# def reminders(request):
#     """Handles creating and retrieving daily reminders for a user."""
    
#     user_id = request.data.get('user')  # Get the user ID from request data

#     if not user_id:
#         return Response({'message': 'User ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

#     try:
#         user = User.objects.get(id=user_id)  # Fetch the user object using user_id
#     except User.DoesNotExist:
#         return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

#     if request.method == 'POST':
#         reminder_time = request.data.get('reminder_time')

#         if not reminder_time:
#             return Response({'message': 'Reminder time is required.'}, status=status.HTTP_400_BAD_REQUEST)

#         reminder = Reminder.objects.create(user=user, reminder_time=reminder_time)
#         return Response({'message': 'Reminder set successfully'}, status=status.HTTP_201_CREATED)

#     elif request.method == 'GET':
#         reminders = Reminder.objects.filter(user=user).order_by('reminder_time')
#         serializer = ReminderSerializer(reminders, many=True)
#         return Response({'reminders': serializer.data}, status=status.HTTP_200_OK)


# @api_view(['GET'])
# def due_reminders(request, user_id):
#     """Fetch reminders that are due for the current time."""
#     current_time = localtime().time()
#     reminders = Reminder.objects.filter(user_id=user_id, reminder_time=current_time)

#     if reminders.exists():
#         return Response({'reminders': True}, status=status.HTTP_200_OK)
#     else:
#         return Response({'reminders': False}, status=status.HTTP_200_OK)





@api_view(['POST', 'GET'])
def report_settings(request, user_id):
    """Allows user to set and retrieve report generation time."""
    # Retrieve the user based on the provided user_id
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        # Get the report time offset (in minutes)
        report_time_offset = request.data.get('report_time_offset')  # in minutes

        # Validate the provided report time offset
        if not report_time_offset or not isinstance(report_time_offset, (int, float)) or report_time_offset < 1:
            return Response({'message': 'Invalid report generation time offset.'}, status=status.HTTP_400_BAD_REQUEST)

        # Calculate the new report time based on the current time and the offset
        new_report_time = now() + timedelta(minutes=report_time_offset)

        # Update or create the ReportSettings for the user
        report_setting, created = ReportSettings.objects.update_or_create(
            user=user, 
            defaults={'report_time': new_report_time}
        )

        # Serialize the report setting and return it
        serializer = ReportSettingsSerializer(report_setting)
        return Response({
            'message': f'Report will be generated at {new_report_time}.',
            'report_settings': serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'GET':
        # Retrieve the report settings for the user
        report_setting = get_object_or_404(ReportSettings, user=user)
        
        # Serialize the report setting and return it
        serializer = ReportSettingsSerializer(report_setting)
        return Response({'report_settings': serializer.data}, status=status.HTTP_200_OK)
    

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def generate_mood_report(request):
#     """Generates a mood report if the set time has been reached."""
#     user = request.user

#     try:
#         report_setting = ReportSettings.objects.get(user=user)
#         report_time = report_setting.report_time
#     except ReportSettings.DoesNotExist:
#         return Response({'message': 'Report time not set. Please configure report settings first.'}, status=status.HTTP_400_BAD_REQUEST)

#     if now() < report_time:
#         return Response({'message': f'Report is not yet ready. It will be available at {report_time}.'}, status=status.HTTP_400_BAD_REQUEST)

#     # Fetch mood entries since the last report was generated
#     mood_entries = MoodEntry.objects.filter(user=user, date__gte=report_time - timedelta(days=7))
#     serializer = MoodEntrySerializer(mood_entries, many=True)

#     # Automatically reset the report time to avoid duplicate reports
#     report_setting.report_time = now() + timedelta(minutes=1)  # Reset to default (1 min later)
#     report_setting.save()

#     return Response({
#         'message': 'Mood report generated.',
#         'mood_entries': serializer.data
#     }, status=status.HTTP_200_OK)  
    

def generate_mood_report(request, user_id):
    # Ensure this only fetches the user with the given ID
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return HttpResponse("User not found", status=404)

    # Fetch mood entries of that user
    moods = MoodEntry.objects.filter(user=user).order_by('-date')

    # Create a PDF response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{user.username}_mood_report.pdf"'

    # Create a canvas for the report
    pdf = canvas.Canvas(response, pagesize=letter)
    pdf.setTitle(f"Mood Report - {user.username}")

    # Title
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, 750, "Mood Report")

    # User Details
    pdf.setFont("Helvetica", 12)
    pdf.drawString(100, 720, f"User ID: {user.id}")
    pdf.drawString(100, 700, f"Name: {user.first_name} {user.last_name}")
    pdf.drawString(100, 680, f"Email: {user.email}")

    # Table Header
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(100, 650, "Date")
    pdf.drawString(250, 650, "Mood Description")

    # Table Content
    pdf.setFont("Helvetica", 10)
    y = 630
    for mood in moods:
        # pdf.drawString(100, y, str(mood.date))
        pdf.drawString(100, y, mood.date.strftime("%Y-%m-%d %I:%M %p"))
        pdf.drawString(250, y, mood.mood_description[:50])  # Limit text for display
        y -= 20

        if y < 50:  # Add a new page if content exceeds the limit
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = 750

    pdf.save()
    return response


@api_view(['GET'])
def report_status(request, user_id):
    """Returns the report generation status for a user."""
    report_setting = get_object_or_404(ReportSettings, user_id=user_id)
    report_time = report_setting.report_time

    if now() < report_time:
        return Response({"status": "pending", "report_time": report_time}, status=status.HTTP_200_OK)

    return Response({"status": "ready"}, status=status.HTTP_200_OK)



@api_view(['POST', 'GET'])
def journal_entries(request):
    if request.method == 'POST':
        # Get the journal_description from the request data
        journal_description = request.data.get('journal_description')
        # Get the user_id (which is passed from the frontend)
        user_id = request.data.get('user')
        
        # Validate that journal_description is provided
        if not journal_description:
            return Response({
                'message': 'Journal description is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Query the User model to ensure the user exists
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'message': 'User not found.'
            }, status=status.HTTP_404_NOT_FOUND)

        # If the user is found, create the journal entry
        try:
            data = JournalEntry.objects.create(
                journal_description=journal_description,
                user=user  # Use the queried user instance
            )
            data.save()
        except Exception as e:
            return Response({
                'message': f'Error saving journal entry: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'message': 'Journal added successfully',
        }, status=status.HTTP_201_CREATED)

    elif request.method == 'GET':
        # Retrieve all journal entries
        journal_entries = JournalEntry.objects.all()

        # Serialize the journal entries (you should have a JournalEntrySerializer)
        serializer = JournalEntrySerializer(journal_entries, many=True)
        
        return Response({
            'journal_entries': serializer.data
        }, status=status.HTTP_200_OK)


@api_view(['GET', 'PUT', 'DELETE'])
def journal_entries_detail(request, user_id):
    """Handles retrieving, updating, and deleting journal entries for a user."""
    
    # Get the user or return a 404 error
    user = get_object_or_404(User, id=user_id)

    if request.method == 'GET':
        # Retrieve and serialize journal entries for the user
        journal_entries = JournalEntry.objects.filter(user=user).order_by('-id')
        serializer = JournalEntrySerializer(journal_entries, many=True)
        return Response({'journal_entries': serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        # Extract journal entry details from request data
        journal_id = request.data.get('journal_id')
        journal_description = request.data.get('journal_description')

        if not journal_id or not journal_description:
            return Response({'message': 'Journal ID and description are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve journal entry or return 404
        journal_entry = get_object_or_404(JournalEntry, id=journal_id, user=user)

        # Update the journal entry
        journal_entry.journal_description = journal_description
        journal_entry.save()

        # Serialize and return the updated journal entry
        serializer = JournalEntrySerializer(journal_entry)
        return Response({
            'message': 'Journal entry updated successfully.',
            'updated_journal_entry': serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'DELETE':
        # Extract journal ID from request data
        journal_id = request.data.get('journal_id')
        if not journal_id:
            return Response({'message': 'Journal ID is required for deletion.'}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve journal entry or return 404
        journal_entry = get_object_or_404(JournalEntry, id=journal_id, user=user)
        journal_entry.delete()

        return Response({'message': 'Journal entry deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    
    
@api_view(['POST', 'GET'])
def post_list_create(request):
    if request.method == 'POST':
        content = request.data.get('content')
        user_id = request.data.get('user')

        if not content:
            return Response({'message': 'Content is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            post = Post.objects.create(content=content, user=user)

            # Get all users except the post creator
            other_users = User.objects.exclude(id=user.id)

            # Create a notification and associate it with these users
            notification = Notification.objects.create(
                post=post,
                # message=f"{user.username} added a new post."
                message=f"Anonymous added a new post."
            )
            notification.users.set(other_users)  # Attach all users except creator

            return Response({'message': 'Post created successfully.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'message': f'Error creating post: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'GET':
        posts = Post.objects.all().order_by('-id')
        serializer = PostSerializer(posts, many=True)
        return Response({'posts': serializer.data}, status=status.HTTP_200_OK)



@api_view(['GET', 'PUT', 'DELETE'])
def post_detail(request, user_id):
    try:
        # Query the user using the primary key (user_id)
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({
            'message': 'User not found.'
        }, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # Retrieve all posts for the given user
        posts = Post.objects.filter(user=user).order_by('-id')

        # Serialize the posts (you should have a PostSerializer)
        serializer = PostSerializer(posts, many=True)
        
        return Response({
            'posts': serializer.data
        }, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        # Ensure the request contains the post ID and content
        post_id = request.data.get('id')
        content = request.data.get('content')

        if not post_id or not content:
            return Response({
                'message': 'Post ID and content are required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the post to update
            post = Post.objects.get(id=post_id, user=user)

            # Update the post content
            post.content = content
            post.save()

            # Serialize the updated post
            serializer = PostSerializer(post)
            
            return Response({
                'message': 'Post updated successfully.',
                'updated_post': serializer.data
            }, status=status.HTTP_200_OK)

        except Post.DoesNotExist:
            return Response({
                'message': 'Post not found for this user.'
            }, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        # Ensure the request contains the post ID
        post_id = request.data.get('post_id')

        if not post_id:
            return Response({
                'message': 'Post ID is required.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the post to delete
            post = Post.objects.get(id=post_id, user=user)

            # Delete the post
            post.delete()

            return Response({
                'message': 'Post deleted successfully.'
            }, status=status.HTTP_204_NO_CONTENT)

        except Post.DoesNotExist:
            return Response({
                'message': 'Post not found for this user.'
            }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def user_notifications(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Get notifications where this user is still included
    notifications = Notification.objects.filter(users=user).order_by('-created_at')
    unread_count = Notification.objects.filter(users=user).count()
    serializer = NotificationSerializer(notifications, many=True)
    
    return Response({'notifications': serializer.data,'unread_count':unread_count}, status=status.HTTP_200_OK)




@api_view(['POST'])
def mark_notification_read(request, notification_id, user_id):
    try:
        user = User.objects.get(id=user_id)
        notification = Notification.objects.get(id=notification_id)

        # Remove user from notification
        notification.users.remove(user)
        return Response({'message': 'Notification marked as read.'}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    except Notification.DoesNotExist:
        return Response({'message': 'Notification not found.'}, status=status.HTTP_404_NOT_FOUND)




@api_view(['POST', 'GET'])
def comment_list_create(request):
    if request.method == 'POST':
        post_id = request.data.get('post')
        user_id = request.data.get('user')
        content = request.data.get('content')

        if not content:
            return Response({'message': 'Content is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            post = Post.objects.get(id=post_id)
        except Post.DoesNotExist:
            return Response({'message': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            comment = Comment.objects.create(post=post, user=user, content=content)
            comment.save()
            return Response({'message': 'Comment created successfully.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'message': f'Error creating comment: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'GET':
        post_id = request.query_params.get('post_id')
        if not post_id:
            return Response({'message': 'Post ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            post = Post.objects.get(id=post_id)
        except Post.DoesNotExist:
            return Response({'message': 'Post not found.'}, status=status.HTTP_404_NOT_FOUND)

        comments = Comment.objects.filter(post=post).order_by('-created_at')
        serializer = CommentSerializer(comments, many=True)
        return Response({'comments': serializer.data}, status=status.HTTP_200_OK)



@api_view(['GET', 'PUT', 'DELETE'])
def comment_detail(request, comment_id):
    try:
        comment = Comment.objects.get(id=comment_id)
    except Comment.DoesNotExist:
        return Response({'message': 'Comment not found.'}, status=status.HTTP_404_NOT_FOUND)

    # Check if the request user matches the user who created the comment
    user_id = request.data.get('user')
    if user_id != comment.user.id:
        return Response({'message': 'You are not authorized to modify this comment.'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        # Serialize the comment
        serializer = CommentSerializer(comment)
        return Response({'comment': serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        content = request.data.get('content')
        if not content:
            return Response({'message': 'Content is required to update.'}, status=status.HTTP_400_BAD_REQUEST)

        comment.content = content
        comment.save()
        serializer = CommentSerializer(comment)
        return Response({'message': 'Comment updated successfully.', 'updated_comment': serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'DELETE':
        comment.delete()
        return Response({'message': 'Comment deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)




@api_view(['GET', 'PUT'])
def user_detail(request, user_id):
    """Handles retrieving and updating user details."""

    # Get the user or return a 404 error
    user = get_object_or_404(User, id=user_id)

    if request.method == 'GET':
        # Retrieve user details
        user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email
        }
        return Response({'user': user_data}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        # Extract user details from request data
        first_name = request.data.get('first_name', user.first_name)
        last_name = request.data.get('last_name', user.last_name)
        username = request.data.get('username', user.username)
        email = request.data.get('email', user.email)

        # Update user details
        user.first_name = first_name
        user.last_name = last_name
        user.username = username
        user.email = email
        user.save()

        updated_user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email
        }

        return Response({
            'message': 'User details updated successfully.',
            'updated_user': updated_user_data
        }, status=status.HTTP_200_OK)
        
        
#change password
@api_view(['POST'])
def change_password(request, user_id):
    """Handles changing the user password."""
    user = get_object_or_404(User, id=user_id)
    
    # Get the old password, new password, and confirm new password from the request data
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')
    
    # Ensure the old password and new passwords are provided
    if not old_password or not new_password or not confirm_password:
        return Response({'message': 'Old password, new password, and confirm password are required.'}, 
                        status=status.HTTP_400_BAD_REQUEST)

    # Check if the new password and confirm password match
    if new_password != confirm_password:
        return Response({'message': 'New password and confirm password do not match.'}, 
                        status=status.HTTP_400_BAD_REQUEST)
    
    # Check if the old password is correct
    if not user.check_password(old_password):
        return Response({'message': 'Old password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

    # Update password
    user.set_password(new_password)
    user.save()
    
    # Keep the user logged in after password change
    update_session_auth_hash(request, user)
    
    return Response({'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)



# =======================for verify password================================

@csrf_exempt  # Remove this in production if using CSRF properly
def verify_password(request, id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            current_password = data.get("current_password")

            # Fetch user from database
            user = User.objects.get(id=id)

            # Verify if the current password is correct
            if check_password(current_password, user.password):
                return JsonResponse({"message": "Password verified successfully"}, status=200)
            else:
                return JsonResponse({"error": "Incorrect current password"}, status=400)
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt  # Remove this in production if using CSRF properly
def change_password(request, id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            current_password = data.get("current_password")
            new_password = data.get("new_password")

            # Fetch user from database
            user = User.objects.get(id=id)

            # Check if the provided current password is correct
            if not check_password(current_password, user.password):
                return JsonResponse({"error": "Incorrect current password"}, status=400)

            # Update user's password securely
            user.password = make_password(new_password)
            user.save()

            return JsonResponse({"message": "Password changed successfully"}, status=200)
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

def csrf_token(request):
    return JsonResponse({"csrfToken": get_token(request)})



#============for password reset code ===================
class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            otp = str(random.randint(100000, 999999))
            PasswordResetOTP.objects.create(user=user, otp=otp)

            send_mail(
                "Password Reset OTP",
                f"Your OTP is {otp}. It is valid for 10 minutes.",
                "noreply@example.com",
                [email],
                fail_silently=False,
            )

            return Response({"message": "OTP sent to your email"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            user = User.objects.get(email=email)
            otp_entry = PasswordResetOTP.objects.filter(user=user, otp=otp).first()

            if otp_entry and otp_entry.is_valid():
                return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']

            user = User.objects.get(email=email)
            otp_entry = PasswordResetOTP.objects.filter(user=user, otp=otp).first()

            if otp_entry and otp_entry.is_valid():
                user.set_password(new_password)
                user.save()
                otp_entry.delete()  # Remove OTP after use

                return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    

#==========Chat with AI====================================#


@api_view(['POST', 'GET'])
def chat_with_ai(request, user_id):
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'POST':
        message = request.data.get('message')
        if not message:
            return Response({'error': 'Message is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get AI response from OpenAI
            response = get_openai_response(message)
            print(response)
            # Save to database
            ChatMessage.objects.create(user=user, message=message, response=response)
            return Response({'user_message': message, 'ai_response': response}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    elif request.method == 'GET':
        chats = ChatMessage.objects.filter(user=user)
        chat_data = [
            {'user': chat.user.username, 'message': chat.message, 'response': chat.response, 'timestamp': chat.timestamp}
            for chat in chats
        ]
        return Response({'chats': chat_data}, status=status.HTTP_200_OK)

def get_openai_response(user_input):
    print(user_input)
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # or "gpt-4"
            messages=[
                {"role": "system", "content": "You are a mental health assistant. Provide supportive and empathetic responses."},
                {"role": "user", "content": user_input}
            ]
        )
        return response.choices[0].message['content']
    except Exception as e:
        return f"AI Error: {str(e)}"






@api_view(['POST', 'GET'])
def set_reminder(request, user_id):
    user = User.objects.get(id=user_id)
    
    if request.method == 'POST':
        hour = request.data.get('hour')
        minute = request.data.get('minute')
        am_pm = request.data.get('am_pm')
        
        if not all([hour, minute, am_pm]):
            return Response({'message': 'Hour, minute, and AM/PM are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        reminder, created = Reminder.objects.update_or_create(
            user=user,
            defaults={
                'hour': hour,
                'minute': minute,
                'am_pm': am_pm
            }
        )
        
        return Response({'message': 'Reminder set successfully'}, status=status.HTTP_200_OK)
    
    elif request.method == 'GET':
        reminder = Reminder.objects.filter(user=user).first()
        if reminder:
            return Response({
                'hour': reminder.hour,
                'minute': reminder.minute,
                'am_pm': reminder.am_pm
            }, status=status.HTTP_200_OK)
        return Response({'message': 'No reminder set'}, status=status.HTTP_404_NOT_FOUND)

import schedule
import time as t
from django.core.management.base import BaseCommand

from django.utils.timezone import localtime
from datetime import datetime

def check_reminders():
    # Get the current time in 24-hour format
    current_time = localtime().strftime('%H:%M')
    hour, minute = map(int, current_time.split(':'))

    # Fetch all reminders and compare the current time with each one
    reminders = Reminder.objects.all()

    for reminder in reminders:
        # Get reminder time in 24-hour format
        reminder_hour = reminder.get_24_hour_format()
        reminder_minute = reminder.minute

        # Check if the current time matches the reminder time
        if hour == reminder_hour and minute == reminder_minute:
            print(f"Triggering reminder for {reminder.user.username} at {reminder_hour}:{reminder_minute}")

            # Add your notification logic here, like triggering a frontend popup or email



class Command(BaseCommand):
    help = 'Runs the reminder checker every minute'

    def handle(self, *args, **kwargs):
        schedule.every().minute.do(check_reminders)
        while True:
            schedule.run_pending()
            t.sleep(60)