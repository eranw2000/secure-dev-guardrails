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


def responses(request):
    Response(**request.json)
    collections.OrderedDict(**request.json)


class FieldsOnTheClass(serializers.ModelSerializer):
    fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class HelperMeta(serializers.ModelSerializer):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class MetaBuiltInAMethod(serializers.ModelSerializer):
    def build(self):
        class Meta:
            fields = "__all__"
        return Meta

    class Meta:
        model = Account
        fields = ["id"]


# A Meta that belongs to a helper class inside each serializer or form shape. Each class also
# has its own Meta with a field list, because a helper Meta is only mistaken for the class's own
# Meta when the class has one.
class HelperBare(ModelSerializer):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class HelperLinkedBare(HyperlinkedModelSerializer):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class HelperLinkedDotted(serializers.HyperlinkedModelSerializer):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class HelperFormBare(ModelForm):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]


class HelperFormDotted(forms.ModelForm):
    class Helper:
        class Meta:
            fields = "__all__"

    class Meta:
        model = Account
        fields = ["id"]
