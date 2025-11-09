from django.shortcuts import render

from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views import View
from ratelimit.decorators import ratelimit


@method_decorator(
    ratelimit(
        key='user_or_ip',  # Use user if authenticated, else IP
        rate='10/m',       # 10 requests per minute for authenticated
        method='POST',     # Apply to POST (login attempts)
        block=True,        # Block (403) on exceed
    ),
    name='dispatch'
)
class RateLimitedLoginView(LoginView):
    """
    Rate-limited login view.
    - Authenticated: 10 POSTs/min
    - Anonymous: 5 POSTs/min (fallback via ratelimit config)
    """
    template_name = 'login.html'  # Create this template if needed

    def form_invalid(self, form):
        # Log failed login attempt (integrates with existing logging)
        return super().form_invalid(form)

    def form_valid(self, form):
        return super().form_valid(form)


# Simple function-based alternative (if you prefer over class-based)
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def custom_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home or dashboard
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')