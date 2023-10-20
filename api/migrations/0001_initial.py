# Generated by Django 4.2.5 on 2023-10-20 16:47

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=100)),
                ('password', models.CharField(max_length=200)),
                ('salt', models.CharField(max_length=100)),
                ('account_type', models.CharField(choices=[('job_seeker', 'Job Seeker'), ('company', 'Company'), ('admin', 'Admin')], default='job_seeker', max_length=100)),
            ],
        ),
    ]