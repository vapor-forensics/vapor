from celery import shared_task
from .models import AWSAccount
from .utils import pull_aws_resources
import logging

logger = logging.getLogger('aws_tasks')

# This is a background task to pull AWS resources for a given account ID.
@shared_task
def pull_aws_resources_task(account_id):
    """
    Background task to pull AWS resources for a given account ID.
    """
    try:
        logger.info(f"Starting resource pull for AWS account ID: {account_id}")
        aws_account = AWSAccount.objects.get(id=account_id)
        pull_aws_resources(aws_account)
        logger.info(f"Successfully pulled resources for AWS account ID: {account_id}")
        return f"Resources for AWS account {aws_account.account_id} pulled successfully."
    except AWSAccount.DoesNotExist:
        logger.error(f"AWSAccount with ID {account_id} does not exist.")
        return f"AWSAccount with ID {account_id} does not exist."
    except Exception as e:
        logger.error(f"Error pulling resources for AWS account ID {account_id}: {e}")
        raise
