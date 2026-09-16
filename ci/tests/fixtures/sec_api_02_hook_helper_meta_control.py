from rest_framework import serializers


class S(serializers.ModelSerializer):
    class Helper:
        class Meta:
            fields = "__all__"

    def build(self):
        class Meta:
            fields = "__all__"
        return Meta
