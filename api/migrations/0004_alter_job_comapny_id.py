# Generated by Django 4.2.5 on 2023-10-23 22:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_application'),
    ]

    operations = [
        migrations.AlterField(
            model_name='job',
            name='comapny_id',
            field=models.IntegerField(unique=True),
        ),
    ]