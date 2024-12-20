from django.http import HttpResponse


class HealthCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # this path exists to allow kamal (or another service) to check if the app is healthy without running
        # any security checks.
        # you can modify this path if you need to.
        if request.path == "/up":
            # You can also perform any "real" health checking here if needed
            response = HttpResponse("OK")
        else:
            response = self.get_response(request)
        return response
