from rest_framework import serializers


class S(serializers.ModelSerializer):
    class Meta:
        fields = ["id"]


fields = "__all__"
