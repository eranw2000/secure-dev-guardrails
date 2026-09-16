import django_filters
from rest_framework import serializers


class S(serializers.ModelSerializer):
    class Meta:
        fields = ["name"]


class F(django_filters.FilterSet):
    class Meta:
        fields = "__all__"
