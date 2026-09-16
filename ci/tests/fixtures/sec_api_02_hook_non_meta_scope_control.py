from rest_framework import serializers


class S(serializers.ModelSerializer):
    class Config:
        fields = "__all__"

    def get_field_names(self, declared_fields, info):
        fields = "__all__"
        return fields

    class Meta:
        fields = ["id"]
