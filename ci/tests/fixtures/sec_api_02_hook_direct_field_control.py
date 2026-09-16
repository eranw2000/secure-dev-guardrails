from rest_framework import serializers


class S(serializers.ModelSerializer):
    fields = "__all__"

    class Meta:
        fields = ["id"]
