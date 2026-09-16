# Deliberately insecure: each marked line is a SEC-API-02 case the semgrep rules must report.
from django.forms import ModelForm
from rest_framework import serializers


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


class AccountForm(ModelForm):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02


def create_account(request):
    Account.objects.create(**request.data)  # EXPECT SEC-API-02


def update_account(request, pk):
    Account.objects.filter(pk=pk).update(**request.POST.dict())  # EXPECT SEC-API-02


def upsert_account(request, pk):
    Account.objects.update_or_create(pk=pk, defaults=request.data)  # EXPECT SEC-API-02


def flask_create(request):
    Account.objects.create(**request.get_json())  # EXPECT SEC-API-02


def copy_fields(request, account):
    for key, value in request.data.items():  # EXPECT SEC-API-02
        setattr(account, key, value)
    account.save()
