# Deliberately insecure: each marked line is a SEC-API-02 case the semgrep rules must report.
# One case per pattern and per allowed name, so deleting any of them turns a check red.
from django.forms import ModelForm
from rest_framework import serializers
from rest_framework.serializers import HyperlinkedModelSerializer, ModelSerializer


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


class PlainSerializer(ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


class LinkedSerializer(HyperlinkedModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


class AccountForm(ModelForm):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


def orm_create(request):
    Account.objects.create(**request.data)  # EXPECT SEC-API-02


def orm_get_or_create(request):
    Account.objects.get_or_create(**request.data)  # EXPECT SEC-API-02


def orm_update(request, pk):
    Account.objects.filter(pk=pk).update(**request.POST.dict())  # EXPECT SEC-API-02


def orm_update_or_create(request, pk):
    Account.objects.update_or_create(pk=pk, defaults=request.data)  # EXPECT SEC-API-02


def flask_constructor(request):
    return Account(**request.json)  # EXPECT SEC-API-02


def flask_constructor_call(request):
    return models.Account(**request.get_json())  # EXPECT SEC-API-02


def copy_fields(request, account):
    for key, value in request.data.items():  # EXPECT SEC-API-02
        setattr(account, key, value)


def copy_json_fields(request, account):
    for key, value in request.get_json().items():  # EXPECT SEC-API-02
        setattr(account, key, value)


def orm_create_from_call(request):
    Account.objects.create(**request.get_json())  # EXPECT SEC-API-02


def orm_defaults_from_call(request, pk):
    Account.objects.update_or_create(pk=pk, defaults=request.get_json())  # EXPECT SEC-API-02


def constructor_from_chained_call(request):
    return Account(**request.data.dict())  # EXPECT SEC-API-02


class Outer:
    class NestedSerializer(serializers.ModelSerializer):
        class Meta:
            model = Account
            fields = "__all__"  # EXPECT SEC-API-02


class WrappedSerializer(
    serializers.ModelSerializer,
):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02
