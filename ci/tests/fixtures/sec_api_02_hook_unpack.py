def v(request):
    Account.objects.create(**request.data)
