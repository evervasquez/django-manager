=====
djando-manager
=====

Aplicación para cambiar los persmisos a modulos.

Quick start
-----------

1. Add "polls" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'manager',
    ]
   
2. Incluir en tu settings

```

AUTH_USER_MODEL = 'manager.Users'

AUTHENTICATION_BACKENDS = (
    'manager.backends.ModelBackend',
    )
    
```
