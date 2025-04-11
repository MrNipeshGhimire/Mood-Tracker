from django.urls import path
from .views import set_reminder,register_user, login_user, user_profile, logout_user,mood_entries,journal_entries,journal_entries_detail,post_detail,post_list_create,comment_detail,comment_list_create,user_detail,change_password,PasswordResetRequestView,VerifyOTPView,ResetPasswordView, chat_with_ai,mood_entries_detail,report_settings,generate_mood_report,report_status,user_notifications,mark_notification_read

urlpatterns = [
    path('auth/register/', register_user, name="register"),
    path('auth/login/', login_user, name="login"),
    path('auth/logout/', logout_user, name="logout_user"),
    path('auth/profile/', user_profile, name="profile"),
    path('mood_entry/', mood_entries, name="mood_entry"),
    path('journal_entry/', journal_entries, name="journal_entry"),
    path('journal_entry/<int:user_id>/', journal_entries_detail, name="journal_entry"),
    
    path('posts/', post_list_create, name='post-list-create'),
    path('posts/<int:user_id>/', post_detail, name='post-detail-update'),
     # URL for creating a comment and fetching all comments for a specific post
    path('comments/', comment_list_create, name='comment_list_create'),
    
    # URL for retrieving, updating, or deleting a specific comment
    path('comments/<int:comment_id>/', comment_detail, name='comment_detail'),
    
    path('user/<int:user_id>/', user_detail, name='user-detail'),  # Get & Update User Details
    path('user/<int:user_id>/change-password/', change_password, name='change-password'),
    
     #========= forgot password ===========
    path('forgot-password/', PasswordResetRequestView.as_view(), name='forgot-password'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('chat/', chat_with_ai, name='chat_with_ai'),
    path('chat/<int:user_id>/', chat_with_ai, name='chat_with_ai'),
    
    path('mood-entries/', mood_entries, name='mood_entries'),
    path('mood-entries/<int:mood_id>/', mood_entries_detail, name='mood_entries_detail'),
    path('report-settings/<int:user_id>/', report_settings, name='report_settings'),
    path('generate-report/<int:user_id>/', generate_mood_report, name='generate_mood_report'),
    path('report-status/<int:user_id>/', report_status, name='report_status'),

    path('notifications/<int:user_id>/', user_notifications, name='user_notifications'),
    path('notifications/read/<int:notification_id>/<int:user_id>/', mark_notification_read, name='mark_notification_read'),
    
    
    path('reminders/<int:user_id>/', set_reminder, name='set_reminder'),
    
]
