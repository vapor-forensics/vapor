import boto3
from .models import AWSResource
from datetime import datetime


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


# Recursively serialize resource details to make them JSON-serializable.
# Converts datetime objects and other non-serializable types to strings.
def serialize_resource_details(resource):

    if isinstance(resource, dict):
        return {key: serialize_resource_details(value) for key, value in resource.items()}
    elif isinstance(resource, list):
        return [serialize_resource_details(item) for item in resource]
    elif isinstance(resource, datetime):
        return resource.isoformat()  # Convert datetime to ISO 8601 string
    else:
        return resource

 #Discover and save AWS resources for an account, more can be added, but update IAM Policy.
def pull_aws_resources(aws_account):

    session = boto3.Session(
        aws_access_key_id=aws_account.aws_access_key,
        aws_secret_access_key=aws_account.aws_secret_key,
        region_name=aws_account.aws_region
    )

    # Discover EC2 instances
    def fetch_ec2_instances():
        ec2 = session.client('ec2')
        instances = ec2.describe_instances()
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                yield {
                    'resource_id': instance['InstanceId'],
                    'resource_type': 'EC2',
                    'resource_name': next(
                        (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
                        None
                    ),
                    'resource_details': serialize_resource_details(instance),
                    'aws_region': aws_account.aws_region,
                }

    # Discover S3 buckets
    def fetch_s3_buckets():
        s3 = session.client('s3')
        buckets = s3.list_buckets()
        for bucket in buckets.get('Buckets', []):
            yield {
                'resource_id': bucket['Name'],
                'resource_type': 'S3',
                'resource_name': bucket['Name'],
                'resource_details': serialize_resource_details(bucket),
                'aws_region': aws_account.aws_region,
            }

    # Discover IAM users
    def fetch_iam_users():
        iam = session.client('iam')
        users = iam.list_users()
        for user in users.get('Users', []):
            yield {
                'resource_id': user['UserId'],
                'resource_type': 'IAM User',
                'resource_name': user['UserName'],
                'resource_details': serialize_resource_details(user),
                'aws_region': aws_account.aws_region,  # IAM is global
            }

    # Discover IAM roles
    def fetch_iam_roles():
        iam = session.client('iam')
        roles = iam.list_roles()
        for role in roles.get('Roles', []):
            yield {
                'resource_id': role['RoleId'],
                'resource_type': 'IAM Role',
                'resource_name': role['RoleName'],
                'resource_details': serialize_resource_details(role),
                'aws_region': aws_account.aws_region,  # IAM is global
            }

    # Discover Lambda functions
    def fetch_lambda_functions():
        lambda_client = session.client('lambda')
        functions = lambda_client.list_functions()
        for function in functions.get('Functions', []):
            yield {
                'resource_id': function['FunctionArn'],
                'resource_type': 'Lambda Function',
                'resource_name': function['FunctionName'],
                'resource_details': serialize_resource_details(function),
                'aws_region': aws_account.aws_region,
            }

    # Discover RDS instances
    def fetch_rds_instances():
        rds = session.client('rds')
        instances = rds.describe_db_instances()
        for instance in instances.get('DBInstances', []):
            yield {
                'resource_id': instance['DBInstanceIdentifier'],
                'resource_type': 'RDS',
                'resource_name': instance['DBInstanceIdentifier'],
                'resource_details': serialize_resource_details(instance),
                'aws_region': aws_account.aws_region,
            }

    # Collect resources from all services
    resource_generators = [
        fetch_ec2_instances,
        fetch_s3_buckets,
        fetch_iam_users,
        fetch_iam_roles,
        fetch_lambda_functions,
        fetch_rds_instances
    ]

    for generator in resource_generators:
        for resource in generator():
            AWSResource.objects.get_or_create(
                account=aws_account,
                case=aws_account.case,
                resource_id=resource['resource_id'],
                defaults={
                    'resource_type': resource['resource_type'],
                    'resource_name': resource['resource_name'],
                    'resource_details': resource['resource_details'],
                    'aws_region': resource['aws_region'],
                }
            )