def v(request, pk):
    Account.objects.filter(pk=pk).update(**request.data)
