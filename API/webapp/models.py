from django.db import models

class Website(models.Model):
	url=models.CharField(max_length=255)
	rate=models.CharField(max_length=255)

	def __str__(self):
		return self.rate
