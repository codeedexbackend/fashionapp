# Generated by Django 3.2.10 on 2024-04-13 16:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_order_total_price'),
    ]

    operations = [
        migrations.AlterField(
            model_name='order',
            name='payment_method',
            field=models.CharField(choices=[('COD', 'Cash on Delivery'), ('Online', 'Online Payment')], max_length=100),
        ),
    ]