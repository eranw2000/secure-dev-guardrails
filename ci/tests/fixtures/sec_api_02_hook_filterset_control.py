import django_filters


class F(django_filters.FilterSet):
    class Meta:
        fields = "__all__"
