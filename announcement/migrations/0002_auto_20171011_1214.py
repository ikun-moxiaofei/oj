# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-10-11 12:14
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('announcement', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='announcement',
            name='title',
            field=models.CharField(max_length=64),
        ),
        migrations.AlterModelOptions(
            name='announcement',
            options={'ordering': ('-create_time',)},
        ),
    ]
