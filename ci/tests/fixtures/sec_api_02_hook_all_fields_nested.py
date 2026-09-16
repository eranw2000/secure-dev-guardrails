from rest_framework import serializers


class Outer:
    class S(serializers.ModelSerializer):
        class Meta:
            fields = "__all__"
