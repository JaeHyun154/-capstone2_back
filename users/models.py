from django.db import models

class Account(models.Model):
    username = models.CharField(max_length=20)
    email = models.EmailField()
    userID = models.CharField(max_length=20)
    password = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'accounts'
        
# class video(models.model):
