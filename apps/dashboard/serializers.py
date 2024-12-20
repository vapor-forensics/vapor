from rest_framework import serializers


class UserSignupStatsSerializer(serializers.Serializer):
    date = serializers.DateField()
    count = serializers.IntegerField()
