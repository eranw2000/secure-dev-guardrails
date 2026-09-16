# Deliberately insecure: a model form whose base class is not imported in this file.


class AccountForm(ModelForm):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02
