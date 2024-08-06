from django.shortcuts import render
from . import spoof

def index(request):
    results = None
    if request.method == "GET":
        return render(request, "index.html", {"results": results})
    if request.method == "POST":
        broadcast_address = request.POST.get("broadcast")
        results = spoof.scan_network(broadcast_address)
    
    return render(request, "index.html", {"results": results})

