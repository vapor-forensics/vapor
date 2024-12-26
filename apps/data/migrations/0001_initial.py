# Generated by Django 5.1.3 on 2024-12-25 11:56

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('aws', '0001_initial'),
        ('case', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='NormalizedLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_source', models.CharField(choices=[('aws', 'Amazon Web Services'), ('gcp', 'Google Cloud Platform'), ('azure', 'Microsoft Azure')], max_length=50)),
                ('log_type', models.CharField(max_length=100)),
                ('event_name', models.CharField(max_length=255)),
                ('event_time', models.DateTimeField()),
                ('user_identity', models.JSONField(blank=True, null=True)),
                ('resources', models.JSONField(blank=True, null=True)),
                ('raw_data', models.JSONField()),
                ('extra_data', models.JSONField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('aws_resource', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='normalized_logs', to='aws.awsresource')),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='normalized_logs', to='case.case')),
            ],
        ),
    ]
