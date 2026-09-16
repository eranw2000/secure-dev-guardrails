# Deliberately insecure, and deliberately WITHOUT an import of the base class. semgrep resolves an
# imported name back to its module, so the dotted-base pattern alone matches every class in
# sec_api_02_bad.py; only a file with no import exercises the bare-name pattern.


class AccountForm(ModelForm):
    class Meta:
        model = Account
        fields = "__all__"  # EXPECT SEC-API-02
