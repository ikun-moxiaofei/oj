# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-08-30 11:54
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('submission', '0005_submission_username'),
    ]

    operations = [
        migrations.AlterField(
            model_name='submission',
            name='result',
            field=models.IntegerField(db_index=True, default=6),
        ),
    ]
