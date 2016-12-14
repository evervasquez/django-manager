from manager.models import _user_get_all_permissions


def get_modules(request):
    permissions = _user_get_all_permissions(request.user, None)
    print(permissions)
    return {
        'modules': []
    }
