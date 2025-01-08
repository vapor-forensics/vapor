from celery import shared_task
from .models import AWSAccount
from .utils import pull_aws_resources, discover_log_sources
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


logger = logging.getLogger(__name__)

# This background task is used to find available logs for an aws accoutt ID
@shared_task
def pull_log_source_task(account_id):

    try:
        logger.info(f"Starting log source discovery for AWS account ID: {account_id}")
        aws_account = AWSAccount.objects.get(id=account_id)

        # Call the discover_log_sources function
        discover_log_sources(aws_account)

        logger.info(f"Successfully discovered log sources for AWS account ID: {account_id}")
        return f"Log sources for AWS account {aws_account.account_id} discovered successfully."

    except AWSAccount.DoesNotExist:
        logger.error(f"AWSAccount with ID {account_id} does not exist.")
        return f"AWSAccount with ID {account_id} does not exist."

    except Exception as e:
        logger.error(f"Error discovering log sources for AWS account ID {account_id}: {e}")
        raise