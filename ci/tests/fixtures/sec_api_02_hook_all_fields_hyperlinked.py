from rest_framework import serializers


class S(serializers.HyperlinkedModelSerializer):
    class Meta:
        fields = "__all__"
