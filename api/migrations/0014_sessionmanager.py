# Generated by Django 4.2.5 on 2023-10-28 07:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_alter_user_email'),
    ]

    operations = [
        migrations.CreateModel(
            name='SessionManager',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=100)),
                ('createdat', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
