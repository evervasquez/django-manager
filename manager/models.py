from django.contrib import auth
from django.utils import six, timezone
from django.core.exceptions import PermissionDenied
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.core import validators
from django.core.mail import send_mail
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from .mixins import TimeStampedModel

# region MANAGERS


class MyUserManager(BaseUserManager):
    def _create_user(self, username, email, password, **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, email, password, **extra_fields)


class GroupManager(models.Manager):
    """
    The manager for the auth's Group model.
    """
    use_in_migrations = True

    def get_by_natural_key(self, name):
        return self.get(name=name)


class PermissionManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, codename, app_label, model):
        return self.get(
            codename=codename,
            content_type=ContentType.objects.db_manager(self.db).get_by_natural_key(app_label, model),
        )
# endregion


@python_2_unicode_compatible
class Permissions(models.Model):
    name = models.CharField(_('name'), max_length=255)
    content_type = models.ForeignKey(
        ContentType,
        models.CASCADE,
        verbose_name=_('content_type'),
        related_name=_('content_type'),
        null=True,
        blank=True
    )
    codename = models.CharField(_('codename'), max_length=100,
                                help_text="example: add=add_[module], "
                                          "delete=delete_[module], "
                                          "list=list_[module], "
                                          "edit=edit_[module]")
    objects = PermissionManager()

    module = models.ForeignKey(
        'Modules',
        models.CASCADE,
        verbose_name=_('modules')
    )

    class Meta:
        verbose_name = _('Permiso')
        verbose_name_plural = _('Permisos')
        unique_together = (('content_type', 'codename'),)
        ordering = ('content_type__app_label', 'content_type__model',
                    'codename')

    def __str__(self):

        return "%s | %s" % (
            six.text_type(self.module.name),
            six.text_type(self.name))

    def natural_key(self):
        return (self.codename,) + self.content_type.natural_key()

    natural_key.dependencies = ['contenttypes.contenttype']


@python_2_unicode_compatible
class Groups(models.Model):
    name = models.CharField(_('name'), max_length=80, unique=True)
    permissions = models.ManyToManyField(
        Permissions,
        verbose_name=_('permissions'),
        blank=True,
    )

    objects = GroupManager()

    class Meta:
        verbose_name = _('Perfil')
        verbose_name_plural = _('Perfiles')

    def __str__(self):
        return self.name

    def natural_key(self):
        return (self.name,)


# A few helper functions for common logic between User and AnonymousUser.
def _user_get_all_permissions(user, obj):
    permissions = set()
    for backend in auth.get_backends():
        if hasattr(backend, "get_all_permissions"):
            permissions.update(backend.get_all_permissions(user, obj))
    return permissions


def _user_has_perm(user, perm, obj):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in auth.get_backends():
        if not hasattr(backend, 'has_perm'):
            continue
        try:
            if backend.has_perm(user, perm, obj):
                return True
        except PermissionDenied:
            return False
    return False


def _user_has_module_perms(user, app_label):
    """
    A backend can raise `PermissionDenied` to short-circuit permission checking.
    """
    for backend in auth.get_backends():
        if not hasattr(backend, 'has_module_perms'):
            continue
        try:
            if backend.has_module_perms(user, app_label):
                return True
        except PermissionDenied:
            return False
    return False


class PermissionsMixins(models.Model):
    is_superuser = models.BooleanField(
        _('superuser status'),
        default=False,
        help_text=_(
            'Designates that this user has all permissions without '
            'explicitly assigning them.'
        ),
    )
    groups = models.ManyToManyField(
        'Groups',
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="user_set",
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        'Permissions',
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="user_set",
        related_query_name="user",
    )

    class Meta:
        abstract = True

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through their
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                permissions.update(backend.get_group_permissions(self, obj))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_all_permissions(self, obj)

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)


class Users(AbstractBaseUser, PermissionsMixins):
    username = models.CharField(
        ('username'),
        max_length=30,
        unique=True,
        help_text=('Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[
            validators.RegexValidator(
                r'^[\w.@+-]+$',
                ('Enter a valid username. This value may contain only '
                 'letters, numbers ' 'and @/./+/-/_ characters.')
            ),
        ],
        error_messages={
            'unique': ("Ya existe usuario con ese nombre"),
        },
    )
    first_name = models.CharField(('first name'), max_length=30, blank=True)
    last_name = models.CharField(('last name'), max_length=30, blank=True)
    email = models.EmailField(('email address'), unique=True,
                              validators=[validators.EmailValidator(message="your custom message")])
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin '
                                               'site.'))
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(('date joined'), default=timezone.now)
    groups = models.ManyToManyField(
        Groups,
        verbose_name=_('groups'),
        blank=True,
        help_text=(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        # related_name="user_set",
        # related_query_name="user",
    )
    is_superuser = models.BooleanField(
        ('superuser status'),
        default=False,
        help_text=(
            'Designates that this user has all permissions without '
            'explicitly assigning them.'
        ),
    )

    user_permissions = models.ManyToManyField(
        Permissions,
        verbose_name=('user permissions'),
        blank=True,
        help_text=('Specific permissions for this user.'),
        related_name="user_set",
        related_query_name="user",
    )
    objects = MyUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    @property
    def full_name(self):
        return '%s %s' % (self.first_name, self.last_name)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def __str__(self):  # __unicode__ on Python 2
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    class Meta:
        verbose_name = "Usuario"
    # @property
    # def is_staff(self):
    #     # "Is the user a member of staff?"
    #     # Simplest possible answer: All admins are staff
    #     return self.is_admin


class Modules(TimeStampedModel):
    app_label = models.CharField(max_length=30, null=True)
    name = models.CharField(max_length=30)
    url = models.CharField(max_length=50)
    icon = models.CharField(max_length=30, null=True, blank=True)
    order = models.PositiveSmallIntegerField(default=0)
    partner = models.ForeignKey('self', null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Módulo"