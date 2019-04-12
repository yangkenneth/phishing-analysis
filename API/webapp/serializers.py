from rest_framework import serializers
from . models import Website


class WebsiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Website
        fields = ("url", "rate")
#        fields = '__all__'