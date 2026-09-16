from rest_framework import serializers


class S(serializers.ModelSerializer):
    """An account serializer."""

    # Every field.
    class Meta:

        fields = "__all__"
