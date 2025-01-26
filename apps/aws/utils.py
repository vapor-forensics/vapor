import boto3
from .models import AWSResource, AWSLogSource, AWSAccount, AWSCredential
from apps.data.models import NormalizedLog
from apps.case.models import Case
from datetime import datetime, timedelta
from django.utils import timezone
import gzip
from botocore.exceptions import EndpointConnectionError, ClientError
import logging
from django.db import transaction
from datetime import timezone
from django.utils.timezone import make_aware
from datetime import datetime, timezone
import time
import json
import ipaddress

logger = logging.getLogger(__name__)

def parse_aws_datetime(datetime_str):
    if datetime_str and datetime_str not in ['N/A', 'not_supported']:
        try:
            dt = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%SZ')
            return make_aware(dt, timezone.utc)
        except ValueError:
            logger.debug(f"Could not parse datetime: {datetime_str}")
            return None
    return None

# Validate AWS credentials by calling the STS GetCallerIdentity API.
def validate_aws_credentials(aws_access_key, aws_secret_key, region):

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        sts = session.client('sts')
        sts.get_caller_identity()  # Validation check
        return True, None
    except Exception as e:
        return False, str(e)


def serialize_resource_details(resource):
    if isinstance(resource, dict):
        return {key: serialize_resource_details(value) for key, value in resource.items()}
    elif isinstance(resource, list):
        return [serialize_resource_details(item) for item in resource]
    elif isinstance(resource, datetime):
        return resource.isoformat()
    else:
        return resource

# Find the resources for the AWS account
def pull_aws_resources(aws_account):
    session = boto3.Session(
        aws_access_key_id=aws_account.aws_access_key,
        aws_secret_access_key=aws_account.aws_secret_key
    )

    # Add new function to fetch IAM credential report
    def fetch_credential_report():
        try:
            iam = session.client('iam')
            
            # Generate credential report - this may take a few seconds
            response = iam.generate_credential_report()
            
            # Wait for report to be generated
            state = response.get('State', '')
            while state != 'COMPLETE':
                logger.info(f"Waiting for credential report to be generated... Current state: {state}")
                time.sleep(2)
                try:
                    response = iam.get_credential_report()
                    state = response.get('State', '')
                except iam.exceptions.CredentialReportNotPresentException:
                    logger.info("Report not ready yet, retrying...")
                    continue
            
            # Get the credential report
            response = iam.get_credential_report()
            if 'Content' not in response:
                logger.error("No content in credential report response")
                return
            
            report_csv = response['Content'].decode('utf-8')
            
            # Parse CSV content
            report_lines = report_csv.split('\n')
            headers = report_lines[0].split(',')
            
            # Process each user's credentials
            for line in report_lines[1:]:
                if not line:
                    continue
                    
                user_data = dict(zip(headers, line.split(',')))
                
                # Create or update AWSCredential record
                AWSCredential.objects.update_or_create(
                    account=aws_account,
                    case=aws_account.case,
                    user=user_data['user'],
                    defaults={
                        'user_arn': user_data.get('arn', ''),
                        'user_creation_time': parse_aws_datetime(user_data.get('user_creation_time')),
                        'password_enabled': user_data.get('password_enabled', 'false').lower() == 'true',
                        'password_last_used': parse_aws_datetime(user_data.get('password_last_used')),
                        'password_last_changed': parse_aws_datetime(user_data.get('password_last_changed')),
                        'password_next_rotation_date': parse_aws_datetime(user_data.get('password_next_rotation')),
                        'mfa_active': user_data.get('mfa_active', 'false').lower() == 'true',
                        'access_key_1_active': user_data.get('access_key_1_active', 'false').lower() == 'true',
                        'access_key_1_last_rotated': parse_aws_datetime(user_data.get('access_key_1_last_rotated')),
                        'access_key_1_last_used_date': parse_aws_datetime(user_data.get('access_key_1_last_used_date')),
                        'access_key_1_last_used_region': user_data.get('access_key_1_last_used_region', ''),
                        'access_key_1_last_used_service': user_data.get('access_key_1_last_used_service', ''),
                        'access_key_2_active': user_data.get('access_key_2_active', 'false').lower() == 'true',
                        'access_key_2_last_rotated': parse_aws_datetime(user_data.get('access_key_2_last_rotated')),
                        'access_key_2_last_used_date': parse_aws_datetime(user_data.get('access_key_2_last_used_date')),
                        'access_key_2_last_used_region': user_data.get('access_key_2_last_used_region', ''),
                        'access_key_2_last_used_service': user_data.get('access_key_2_last_used_service', ''),
                        'cert_1_active': user_data.get('cert_1_active', 'false').lower() == 'true',
                        'cert_1_last_rotated': parse_aws_datetime(user_data.get('cert_1_last_rotated')),
                        'cert_2_active': user_data.get('cert_2_active', 'false').lower() == 'true',
                        'cert_2_last_rotated': parse_aws_datetime(user_data.get('cert_2_last_rotated')),
                    }
                )
            logger.info("Successfully processed credential report")
            
        except Exception as e:
            logger.error(f"Error fetching credential report: {e}")

    # Try to fetch credential report
    fetch_credential_report()

    # Fetch resources by looping through dynamically fetched regions
    def fetch_resources_by_region(service_name, fetch_function):
        try:
            regions = session.get_available_regions(service_name)
        except Exception as e:
            print(f"[ERROR] Failed to fetch regions for {service_name}: {e}")
            return

        for region in regions:
            try:
                client = session.client(service_name, region_name=region)
                print(f"[INFO] Fetching {service_name} resources in region {region}...")
                for resource in fetch_function(client, region):
                    yield resource
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                if error_code == "AuthFailure":
                    print(f"[WARNING] Region {region} is not accessible for {service_name}. Skipping.")
                else:
                    print(f"[ERROR] Error fetching {service_name} resources in {region}: {e}")
                continue

    # EC2 instances
    def fetch_ec2_instances(client, region):
        try:
            instances = client.describe_instances()
            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    resource_region = instance["Placement"]["AvailabilityZone"][:-1]
                    yield {
                        "resource_id": instance["InstanceId"],
                        "resource_type": "EC2",
                        "resource_name": next(
                            (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
                            None
                        ),
                        "resource_details": serialize_resource_details(instance),
                        "aws_region": resource_region,
                    }
        except ClientError as e:
            print(f"[ERROR] Error fetching EC2 instances in {region}: {e}")

    # S3 buckets (global service)
    def fetch_s3_buckets():
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets()
            for bucket in buckets.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_region = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint", "us-east-1")
                yield {
                    "resource_id": bucket_name,
                    "resource_type": "S3",
                    "resource_name": bucket_name,
                    "resource_details": serialize_resource_details(bucket),
                    "aws_region": bucket_region,
                }
        except ClientError as e:
            print(f"[ERROR] Error fetching S3 buckets: {e}")

    # IAM users (global service)
    def fetch_iam_users():
        try:
            iam = session.client("iam")
            users = iam.list_users()
            for user in users.get("Users", []):
                yield {
                    "resource_id": user["UserId"],
                    "resource_type": "IAM User",
                    "resource_name": user["UserName"],
                    "resource_details": serialize_resource_details(user),
                    "aws_region": None,  # Global
                }
        except ClientError as e:
            print(f"[ERROR] Error fetching IAM users: {e}")

    # IAM roles (global service)
    def fetch_iam_roles():
        try:
            iam = session.client("iam")
            roles = iam.list_roles()
            for role in roles.get("Roles", []):
                yield {
                    "resource_id": role["RoleId"],
                    "resource_type": "IAM Role",
                    "resource_name": role["RoleName"],
                    "resource_details": serialize_resource_details(role),
                    "aws_region": None,  # Global
                }
        except ClientError as e:
            print(f"[ERROR] Error fetching IAM roles: {e}")

    # Lambda functions
    def fetch_lambda_functions(client, region):
        try:
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    yield {
                        "resource_id": function["FunctionArn"],
                        "resource_type": "Lambda Function",
                        "resource_name": function["FunctionName"],
                        "resource_details": serialize_resource_details(function),
                        "aws_region": region,
                    }
        except ClientError as e:
            print(f"[ERROR] Error fetching Lambda functions in {region}: {e}")

    # RDS instances
    def fetch_rds_instances(client, region):
        try:
            instances = client.describe_db_instances()
            for instance in instances.get("DBInstances", []):
                yield {
                    "resource_id": instance["DBInstanceIdentifier"],
                    "resource_type": "RDS",
                    "resource_name": instance["DBInstanceIdentifier"],
                    "resource_details": serialize_resource_details(instance),
                    "aws_region": region,
                }
        except ClientError as e:
            print(f"[ERROR] Error fetching RDS instances in {region}: {e}")

    # Map services to their resource-fetching functions
    resource_generators = [
        ("ec2", fetch_ec2_instances),
        ("lambda", fetch_lambda_functions),
        ("rds", fetch_rds_instances),
    ]

    # Handle regional services
    for service_name, fetch_function in resource_generators:
        for resource in fetch_resources_by_region(service_name, fetch_function):
            _, created = AWSResource.objects.get_or_create(
                account=aws_account,
                case=aws_account.case,
                resource_id=resource["resource_id"],
                defaults={
                    "resource_type": resource["resource_type"],
                    "resource_name": resource["resource_name"],
                    "resource_details": resource["resource_details"],
                    "aws_region": resource["aws_region"],
                }
            )
            if created:
                print(f"[INFO] Saved: {resource['resource_name']} ({resource['resource_id']}) in {resource['aws_region']}")

    # Handle global services
    for fetch_function in [fetch_s3_buckets, fetch_iam_users, fetch_iam_roles]:
        for resource in fetch_function():
            _, created = AWSResource.objects.get_or_create(
                account=aws_account,
                case=aws_account.case,
                resource_id=resource["resource_id"],
                defaults={
                    "resource_type": resource["resource_type"],
                    "resource_name": resource["resource_name"],
                    "resource_details": resource["resource_details"],
                    "aws_region": resource["aws_region"],
                }
            )
            if created:
                print(f"[INFO] Saved: {resource['resource_name']} ({resource['resource_id']}) [Global]")


# Find the logging that is used by the account
def discover_log_sources(aws_account):
    """
    Discover available AWS log sources (CloudTrail, CloudWatch, GuardDuty, etc.) across all regions.
    Save them to the AWSLogSource model for future reference.
    """
    logger.info(f"Discovering log sources for AWS account: {aws_account.account_id}")
    
    # Initialize session
    session = boto3.Session(
        aws_access_key_id=aws_account.aws_access_key,
        aws_secret_access_key=aws_account.aws_secret_key,
    )

    log_sources = []

    def fetch_logs_by_region(service_name, fetch_function):
        try:
            regions = session.get_available_regions(service_name)
            logger.info(f"Regions available for {service_name}: {regions}")
        except Exception as e:
            logger.error(f"Failed to fetch regions for {service_name}: {e}")
            return

        for region in regions:
            try:
                client = session.client(service_name, region_name=region)
                logger.info(f"Fetching {service_name} logs in region {region}...")
                for log in fetch_function(client, region):
                    yield log
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                if error_code in ["AuthFailure", "UnrecognizedClientException"]:
                    logger.warning(f"Region {region} is not accessible for {service_name}. Skipping.")
                else:
                    logger.error(f"Error fetching {service_name} logs in {region}: {e}")
                continue

    # Fetch CloudWatch log groups
    def fetch_cloudwatch_logs(client, region):
        try:
            response = client.describe_log_groups()
            log_groups = response.get("logGroups", [])
            if not log_groups:
                logger.info(f"No CloudWatch log groups found in region {region}.")
            for log_group in log_groups:
                logger.info(f"Found CloudWatch log group: {log_group.get('logGroupName')} in region {region}")
                yield {
                    "service_name": "CloudWatch",
                    "log_name": log_group.get("logGroupName"),
                    "log_details": log_group,
                    "status": "Available",
                    "aws_region": region,
                }
        except ClientError as e:
            logger.error(f"Error fetching CloudWatch logs in {region}: {e}")

    # Fetch CloudTrail logs
    def fetch_cloudtrail_logs(client, region):
        try:
            response = client.describe_trails()
            for trail in response.get("trailList", []):
                yield {
                    "service_name": "CloudTrail",
                    "log_name": trail.get("Name"),
                    "log_details": trail,
                    "status": "Enabled" if trail.get("IsMultiRegionTrail") else "Disabled",
                    "aws_region": trail.get("HomeRegion"),
                }
        except ClientError as e:
            logger.error(f"Error fetching CloudTrail logs in {region}: {e}")

    # Fetch GuardDuty detectors (global service)
    def fetch_guardduty_detectors():
        try:
            regions = session.get_available_regions("guardduty")
            for region in regions:
                guardduty_client = session.client("guardduty", region_name=region)
                detectors = guardduty_client.list_detectors().get("DetectorIds", [])
                for detector_id in detectors:
                    yield {
                        "service_name": "GuardDuty",
                        "log_name": detector_id,
                        "log_details": {"DetectorId": detector_id},
                        "status": "Active",
                        "aws_region": region,
                    }
        except ClientError as e:
            logger.error(f"Error fetching GuardDuty logs: {e}")

    # Map services to their log-fetching functions
    log_generators = [
        ("cloudtrail", fetch_cloudtrail_logs),
        ("logs", fetch_cloudwatch_logs),
    ]

    # Handle regional log sources
    for service_name, fetch_function in log_generators:
        for log in fetch_logs_by_region(service_name, fetch_function):
            log_sources.append(log)

    # Handle global log sources (e.g., GuardDuty)
    for log in fetch_guardduty_detectors():
        log_sources.append(log)

    # Save log sources to the database
    for log_source in log_sources:
        _, created = AWSLogSource.objects.update_or_create(
            account=aws_account,
            case=aws_account.case,
            service_name=log_source["service_name"],
            log_name=log_source["log_name"],
            defaults={
                "log_details": log_source["log_details"],
                "status": log_source["status"],
                "aws_region": log_source["aws_region"],
            },
        )
        if created:
            logger.info(f"Saved log source: {log_source['log_name']} ({log_source['service_name']}) in region {log_source['aws_region']}")
        else:
            logger.info(f"Updated log source: {log_source['log_name']} ({log_source['service_name']}) in region {log_source['aws_region']}")

    logger.info(f"Completed discovering log sources for AWS account: {aws_account.account_id}")

def normalize_cloudtrail_event(raw_event, case, aws_account):
    """Helper function to normalize CloudTrail events into a consistent format"""
    # Handle Records array if present
    if 'Records' in raw_event:
        raw_event = raw_event['Records'][0]  # Take the first record
    
    # If this is from LookupEvents API, the actual event is in CloudTrailEvent
    if 'CloudTrailEvent' in raw_event:
        try:
            raw_event = json.loads(raw_event['CloudTrailEvent'])
        except (json.JSONDecodeError, TypeError):
            pass

    # Extract event time
    event_time = raw_event.get('eventTime')
    if event_time:
        event_time = parse_aws_datetime(event_time)

    # Extract user identity - just get the userName
    user_identity = raw_event.get('userIdentity', {})
    username = (
        user_identity.get('userName') or
        user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName') or
        user_identity.get('invokedBy') or
        user_identity.get('type') or
        'Unknown'
    )

    # Get resources directly from CloudTrail event
    resources = raw_event.get('resources', [])
    
    # If no resources field, try to extract from request/response
    if not resources:
        request_params = raw_event.get('requestParameters', {})
        response_elements = raw_event.get('responseElements', {})
        
        # Store as raw data to preserve all information
        if request_params or response_elements:
            resources = [{
                'requestParameters': request_params,
                'responseElements': response_elements
            }]
    
    # Validate and process the source IP address
    source_ip = raw_event.get('sourceIPAddress')
    if source_ip:
        try:
            # This will raise a ValueError if the IP is not valid
            ipaddress.ip_address(source_ip)
        except ValueError:
            logger.debug(f"Invalid source IP: {source_ip}")
            source_ip = None  # Or handle it as needed
    
    # Build normalized log data
    normalized_data = {
        'case': case,
        'aws_account': aws_account,
        'file_name': raw_event.get('s3', {}).get('object', {}).get('key'),
        'event_id': raw_event.get('eventID'),
        'event_time': event_time,
        'event_source': raw_event.get('eventSource'),
        'event_name': raw_event.get('eventName'),
        'event_type': raw_event.get('eventType'),
        'user_identity': username,
        'region': raw_event.get('awsRegion'),
        'ip_address': source_ip,  # Now validated
        'user_agent': raw_event.get('userAgent'),
        'resources': json.dumps(resources),
        'raw_data': json.dumps(raw_event)
    }

    return normalized_data

def fetch_and_normalize_cloudtrail_logs(account_id, resource_id, prefix, start_date, end_date, case_id):
    """Fetch and normalize CloudTrail logs from S3"""
    try:
        aws_account = AWSAccount.objects.get(account_id=account_id)
        case = Case.objects.get(id=case_id)
        resource = AWSResource.objects.get(id=resource_id)
    except (AWSAccount.DoesNotExist, AWSResource.DoesNotExist, Case.DoesNotExist):
        logger.error("Account, Resource, or Case not found.")
        return

    session = boto3.Session(
        aws_access_key_id=aws_account.aws_access_key,
        aws_secret_access_key=aws_account.aws_secret_key,
        region_name=resource.aws_region or aws_account.aws_region
    )
    s3 = session.client("s3")
    bucket_name = resource.resource_name or resource.resource_id

    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()

    if prefix and not prefix.endswith("/"):
        prefix += "/"

    current_date = start_date_obj
    with transaction.atomic():
        while current_date <= end_date_obj:
            date_folder = f"{current_date.year}/{current_date.strftime('%m')}/{current_date.strftime('%d')}/"
            final_prefix = prefix + date_folder

            logger.info(f"Checking prefix '{final_prefix}' in bucket '{bucket_name}'")

            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name, Prefix=final_prefix):
                    for obj in page.get("Contents", []):
                        key = obj["Key"]
                        try:
                            resp = s3.get_object(Bucket=bucket_name, Key=key)
                            raw_body = resp["Body"].read()
                            
                            # Decompress if gzipped
                            if key.endswith(".gz"):
                                file_data = gzip.decompress(raw_body).decode("utf-8")
                            else:
                                file_data = raw_body.decode("utf-8")

                            records = json.loads(file_data).get("Records", [])
                            
                            # Process each record
                            for record in records:
                                try:
                                    normalized_data = normalize_cloudtrail_event(record, case, aws_account)
                                    NormalizedLog.objects.create(**normalized_data)
                                except Exception as e:
                                    logger.error(f"Error processing record: {e}")
                                    continue

                        except Exception as e:
                            logger.error(f"Error processing file {key}: {e}")
                            continue

            except Exception as e:
                logger.error(f"Error processing date {current_date}: {e}")

            current_date += timedelta(days=1)

def fetch_management_event_history(account_id, case_id):
    """Fetch and normalize CloudTrail management events using LookupEvents API"""
    try:
        aws_account = AWSAccount.objects.get(account_id=account_id)
        case = Case.objects.get(id=case_id)
    except (AWSAccount.DoesNotExist, Case.DoesNotExist) as e:
        logger.error(f"Error fetching account or case: {e}")
        return

    session = boto3.Session(
        aws_access_key_id=aws_account.aws_access_key,
        aws_secret_access_key=aws_account.aws_secret_key,
        region_name=aws_account.aws_region
    )
    client = session.client('cloudtrail')
    paginator = client.get_paginator('lookup_events')

    # Create a list to store normalized events before bulk create
    normalized_events = []
    batch_size = 1000  # Process 1000 events at a time

    try:
        for page in paginator.paginate():
            for event in page.get('Events', []):
                try:
                    normalized_data = normalize_cloudtrail_event(event, case, aws_account)
                    # Create NormalizedLog instance but don't save yet
                    normalized_log = NormalizedLog(**normalized_data)
                    normalized_events.append(normalized_log)

                    # When we reach batch_size, bulk create the records
                    if len(normalized_events) >= batch_size:
                        with transaction.atomic():
                            NormalizedLog.objects.bulk_create(normalized_events)
                        normalized_events = []  # Clear the list after bulk create
                        
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    continue

        # Bulk create any remaining events
        if normalized_events:
            with transaction.atomic():
                NormalizedLog.objects.bulk_create(normalized_events)

    except Exception as e:
        logger.error(f"Error fetching management events: {e}")



