=====
django-manager
=====

django-manager es una aplicación Django para personalizar los permisos por módulo.

Quick start
-----------

1. Agregar "django-manager" en tu setting en la parte de INSTALLED_APPS ::

    INSTALLED_APPS = [
        ...
        'manager',
    ]

2. Incluir en tu settings::
```sh
AUTH_USER_MODEL = 'manager.Users'
```

3. Run `python manage.py migrate`
