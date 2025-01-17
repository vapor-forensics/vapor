from celery import shared_task
from .models import AWSAccount
from .utils import pull_aws_resources, discover_log_sources, fetch_management_event_history, fetch_and_normalize_cloudtrail_logs
import logging

logger = logging.getLogger('aws_tasks')
logger = logging.getLogger(__name__)

# This is a background task to pull AWS resources for a given account ID.
@shared_task
def pull_aws_resources_task(account_id):
    """
    Background task to pull AWS resources for a given account ID.
    """
    try:
        logger.info(f"Starting discovery for AWS account ID: {account_id}")
        aws_account = AWSAccount.objects.get(account_id=account_id)
        pull_aws_resources(aws_account)
        discover_log_sources(aws_account)
        logger.info(f"Successfully pulled resources for AWS account ID: {account_id}")
        return f"Resources for AWS account {aws_account.account_id} pulled successfully."
    except AWSAccount.DoesNotExist:
        logger.error(f"AWSAccount with ID {account_id} does not exist.")
        return f"AWSAccount with ID {account_id} does not exist."
    except Exception as e:
        logger.error(f"Error pulling resources for AWS account ID {account_id}: {e}")
        raise


# Celery task that calls the utility to iterate day-by-day and retrieve CloudTrail logs.
@shared_task
def fetch_normalize_cloudtrail_logs_task(account_id, resource_id, prefix, start_date, end_date, case_id):
    fetch_and_normalize_cloudtrail_logs(
        account_id=account_id,
        resource_id=resource_id,
        prefix=prefix,
        start_date=start_date,
        end_date=end_date,
        case_id=case_id
    )

@shared_task
def fetch_management_history_task(account_id, case_id):
    fetch_management_event_history(account_id, case_id)