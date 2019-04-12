from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from . models import Website
from . serializers import WebsiteSerializer
from . featureExtraction import UsefulFeatures
# Create your views here.

class WebsiteList(APIView):
    def get(self, request):
        websites = Website.objects.all()
        print("GET API triggered!!!");
        serializer = WebsiteSerializer(websites, many = True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        features = UsefulFeatures(str(request.data["url"]));
        prediction = features.predict()
        print("POST: " + request.data["url"]);
        print("Phishing ML Models are running...");
        print("prediction is: " + str(prediction));
        a_website = Website.objects.create(
            url=request.data["url"],
            # assign the result of the model to the rate
            rate=prediction
        )
        return Response(
            data=WebsiteSerializer(a_website).data,
            status=status.HTTP_201_CREATED
        )