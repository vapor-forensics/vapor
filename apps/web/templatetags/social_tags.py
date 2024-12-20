from allauth.socialaccount.adapter import get_adapter
from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def get_socialapps(context):
    """
    Returns a list of social authentication apps.

    Usage: `{% get_socialapps as socialapps %}`.

    Then within the template context, `socialapps` will hold
    a list of social app providers configured for the current site.
    """
    providers = get_adapter().list_providers(context["request"])
    for provider in providers:
        # monkey patch logo path to use in template
        provider.logo_path = f"images/socialauth/{provider.id}-logo.svg"
    return list(providers)
