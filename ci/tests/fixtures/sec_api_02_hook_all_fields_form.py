from django.forms import ModelForm


class F(ModelForm):
    class Meta:
        fields = "__all__"
