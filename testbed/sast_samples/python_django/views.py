"""Intentionally vulnerable Django views (academic SAST target)."""
import html

from django.db import connection
from django.http import HttpResponse
from django.shortcuts import redirect


def profile(request, uid):
    name = request.GET.get('name')
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM auth_user WHERE name = '" + name + "'")  # VULN: SQL injection
    return HttpResponse("Hello " + name)                                   # VULN: reflected XSS


def go(request):
    url = request.GET['next']
    return redirect(url)                                                   # VULN: open redirect


def safe(request):
    name = request.GET.get('name', '')
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM auth_user WHERE name = %s", [name])     # parameterized -> safe
    return HttpResponse(html.escape(name))                                 # escaped -> safe
