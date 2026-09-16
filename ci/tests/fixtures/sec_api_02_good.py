# The safe shapes of the same operations. Nothing here may be reported as SEC-API-02.
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
        fields = ["display_name"]


def create_account(request):
    Account.objects.create(display_name=request.data["display_name"], owner=request.user)


def copy_fields(request, account):
    for key in WRITABLE:
        if key in request.data:
            setattr(account, key, request.data[key])
    account.save()
