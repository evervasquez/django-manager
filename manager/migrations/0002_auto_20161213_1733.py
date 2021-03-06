# -*- coding: utf-8 -*-
# Generated by Django 1.10.4 on 2016-12-13 17:33
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='groups',
            options={'verbose_name': 'Perfil', 'verbose_name_plural': 'Perfiles'},
        ),
        migrations.AlterField(
            model_name='permissions',
            name='codename',
            field=models.CharField(help_text='example: add=add_[module], delete=delete_[module], list=list_[module], edit=edit_[module]', max_length=100, verbose_name='codename'),
        ),
    ]
