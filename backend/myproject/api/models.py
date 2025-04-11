from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now, timedelta

# Create your models here.

class MoodEntry(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    mood_description = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mood_entries')

    def __str__(self):
        return f"Mood Entry by {self.user} on {self.date}"
    

class ReportSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='report_settings')
    report_time = models.DateTimeField(default=now)  # User-defined report generation time

    def __str__(self):
        return f"Report Settings for {self.user} (Next Report: {self.report_time})"

    
class JournalEntry(models.Model):
    date = models.DateField(auto_now_add=True)
    journal_description = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='journal_entries')

    def __str__(self):
        return f"Mood Entry by {self.user} on {self.date}"
    

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="posts")
    content = models.TextField()
    created_at = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Post by {self.user.username} on {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on Post {self.post.id}"
    

  # Password Reset OTP          
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        from datetime import timedelta
        from django.utils.timezone import now
        return now() - self.created_at < timedelta(minutes=10)



class ChatMessage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    
class Notification(models.Model):
    post = models.ForeignKey('Post', on_delete=models.CASCADE)
    users = models.ManyToManyField(User, related_name="notifications", blank=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for Post {self.post.id}"
    

class Reminder(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    hour = models.IntegerField()
    minute = models.IntegerField()
    am_pm = models.CharField(max_length=2, choices=[("AM", "AM"), ("PM", "PM")])

    def __str__(self):
        return f"Reminder for {self.user.username} at {self.hour}:{self.minute} {self.am_pm}"

    def get_24_hour_format(self):
        """
        Convert the hour and AM/PM to 24-hour format for easier comparison.
        """
        if self.am_pm == "AM" and self.hour == 12:
            return 0  # 12 AM should be 00 hours in 24-hour format
        elif self.am_pm == "PM" and self.hour != 12:
            return self.hour + 12  # PM hours (except 12) need 12 added
        return self.hour  # Return as is for AM and 12 PM
    
     

class ReportReminder(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    reminder_time = models.DateTimeField()

    def __str__(self):
        return f"Report Reminder for {self.user.username} at {self.reminder_time}"

