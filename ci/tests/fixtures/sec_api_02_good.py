# The safe shapes, and look-alikes that are not model writes. Nothing here is SEC-API-02.
import django_filters
from rest_framework import serializers

WRITABLE = ("display_name", "timezone")


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["id", "display_name", "timezone"]
        read_only_fields = ["id"]


class AccountFilter(django_filters.FilterSet):
    class Meta:
        model = Account
        fields = "__all__"


def create_account(request):
    Account.objects.create(display_name=request.data["display_name"], owner=request.user)


def not_a_model(request, payload, service):
    payload.update(**request.data)
    service.create(**request.data)
    return dict(**request.json)


def copy_fields(request, account):
    for key in WRITABLE:
        if key in request.data:
            setattr(account, key, request.data[key])
