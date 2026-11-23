"""Intentionally vulnerable Django views demonstrating IDOR (academic target).

IDOR (Insecure Direct Object Reference / broken object-level access control):
a request-supplied object id reaches a data lookup with no ownership check, so
any authenticated user can read another user's object by changing the id.
"""
from django.http import JsonResponse


def get_order(request, order_id):
    # VULN: IDOR — fetches the order by id with no ownership/authorization check,
    # so /orders/<any id>/ returns any user's order.
    order = Order.objects.get(pk=order_id)
    return JsonResponse(order.as_dict())


def my_order(request, order_id):
    # Safe: the query is scoped to the authenticated user, so a foreign id yields
    # nothing rather than another user's record.
    order = Order.objects.get(pk=order_id, user=request.user)
    return JsonResponse(order.as_dict())
