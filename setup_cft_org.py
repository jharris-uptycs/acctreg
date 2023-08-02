"""
This script interacts with AWS CloudFormation to create, delete, and check the status of a stack for
integrating Uptycs with your AWS account. It uses Boto3, the AWS SDK for Python,
to make API calls to CloudFormation.

The script accepts command-line arguments to specify the action to perform: Check, Create, or
Delete. It also requires a path to an authentication configuration file downloaded from the
Uptycs console.

Functions:
- check_stack_exists(stack_name): Checks if a CloudFormation stack exists.
- delete_stack(stack_name): Deletes a CloudFormation stack.
- create_cft_stack(stack_name, template_data, params): Creates a CloudFormation stack.
- wait_for_stack_creation(cf_client, stack_id): Waits for the CloudFormation stack creation.
- create_stack_params(cli_args): Creates the parameters for the CloudFormation stack creation.
- main(): Parses command-line arguments and performs actions on the CloudFormation stack.
"""
import datetime
import base64
import urllib
import hashlib
import hmac
import argparse
import os
import json
import time
import sys
import boto3
import botocore
import uuid

TEMPLATE_FILE = "./cloudformation/uptycs-cnapp.json"
STACK_NAME = 'Uptycs-Integration-Setup-Stack1'


def generate_uuid():
    return str(uuid.uuid4())

def delete_secret_if_exists(secret_name):
    try:
        # Initialize the AWS Secrets Manager client
        secrets_manager_client = boto3.client('secretsmanager')

        # Check if the secret exists
        try:
            response = secrets_manager_client.describe_secret(SecretId=secret_name)

            # Delete the secret
            secrets_manager_client.delete_secret(SecretId=secret_name,
                                                 ForceDeleteWithoutRecovery=True)

            print(f"Secret '{secret_name}' deleted from Secrets Manager.")
            return True
        except secrets_manager_client.exceptions.ResourceNotFoundException:
            print(f"Secret '{secret_name}' does not exist in Secrets Manager.")
            return False

    except Exception as e:
        print(f"Error deleting secret '{secret_name}' from Secrets Manager: {e}")
        return False

def write_json_to_secrets_manager(secret_name, filename):
    try:
        # Initialize the AWS Secrets Manager client
        secrets_manager_client = boto3.client('secretsmanager')

        # Read the JSON data from the file
        with open(filename, 'r') as file:
            json_data = json.load(file)
        external_id = generate_uuid()
        json_data['external_id'] = external_id
        # Check if the secret already exists
        try:
            response = secrets_manager_client.describe_secret(SecretId=secret_name)
            # If the secret exists, update it with the new JSON data
            secrets_manager_client.put_secret_value(
                SecretId=secret_name,
                SecretString=json.dumps(json_data)
            )
            print(f"Secret '{secret_name}' updated in Secrets Manager.")
            return response['ARN']
        except secrets_manager_client.exceptions.ResourceNotFoundException:
            # If the secret does not exist, create a new secret with the JSON data
            response = secrets_manager_client.create_secret(
                Name=secret_name,
                SecretString=json.dumps(json_data)
            )
            print(f"Secret '{secret_name}' created in Secrets Manager.")
            return response['ARN']

    except Exception as e:
        print(f"Error writing secret '{secret_name}' to Secrets Manager: {e}")
        return None

def check_apikeys(config):
    print("Checking api credentials")
    with open(config) as api_config_file:
        uptycs_api_params = json.load(api_config_file)

    req_header = gen_api_headers(uptycs_api_params['key'], uptycs_api_params['secret'])
    uptycs_api_url = gen_cloudaccounts_api_url(uptycs_api_params['domain'],uptycs_api_params['domainSuffix'], uptycs_api_params['customerId'])
    status, response = http_get(uptycs_api_url, req_header)
    return status == 200

def get_uptycs_internal_id(url, req_header, account_id):
    params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}
    status, response = http_get(url, req_header, params)
    for item in response['items']:
        if item['tenantId'] == account_id:
            return item['id']

def gen_cloudaccounts_api_url(domain, domainSuffix, customer_id):
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloudAccounts"
    return uptycs_api_url

def gen_api_headers(key, secret):
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    return req_header
def get_uptycs_internal_id(url, req_header, account_id):
    params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}

    status, response = http_get(url, req_header, params)
    for item in response['items']:
        if item['tenantId'] == account_id:
            return item['id']

def http_get(url, headers, params=None):
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))



def remove_illegal_characters(input_string):
    return input_string.replace('=', '').replace('+', '-').replace('/', '_')


def base64_object(input_object):
    input_bytes = json.dumps(input_object).encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    output = remove_illegal_characters(base64_string)
    return output


def create_auth_token(key, secret):
    date = int(datetime.datetime.now().timestamp())
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'iss': key, 'iat': date, 'exp': date + 60}  # Token expires in 60 seconds
    unsigned_token = base64_object(header) + '.' + base64_object(payload)
    signature_hash = hmac.new(secret.encode('utf-8'), unsigned_token.encode('utf-8'),
                              hashlib.sha256)
    signature = base64.b64encode(signature_hash.digest()).decode('utf-8')
    return unsigned_token + '.' + remove_illegal_characters(signature)


def http_post(url, headers, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))

def delete_file(file_path):
    """
    :param filename:
    :type filename:
    :return:
    :rtype:
    """
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File '{file_path}' deleted.")
    else:
        print(f"File '{file_path}' does not exist.")

def check_file_open(filename):
    """
    Check if a filename exists.

    Args:
        filename (str): Name of the file.

    Returns:
        bool: True if file can be opened, False otherwise.
    """
    try:
        with open(filename):
            print(f"File '{filename}' found.")
            return True
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except IOError:
        print(f"Error opening file '{filename}'.")
    finally:
        return

def check_stack_exists(stack_name):
    """
    Check if a CloudFormation stack exists.

    Args:
        stack_name (str): Name of the CloudFormation stack.

    Returns:
        bool: True if stack exists, False otherwise.
    """
    cf_client = boto3.client('cloudformation')
    try:
        cf_client.describe_stacks(StackName=stack_name)
        return True
    except cf_client.exceptions.ClientError as error:
        if 'does not exist' in str(error):
            return False
        else:
            raise error


def delete_stack(stack_name):
    """
    Delete a CloudFormation stack.

    Args:
        stack_name (str): Name of the CloudFormation stack.
    """
    cloudformation_client = boto3.client('cloudformation')

    try:
        cloudformation_client.delete_stack(StackName=stack_name)
        print(f"Deleting stack '{stack_name}' initiated.")
    except cloudformation_client.exceptions.ClientError as e:
        print(f"Failed to delete stack '{stack_name}': {e.response['Error']['Message']}")


def create_cft_stack(stack_name: str, template_data: str, params: list):
    """
    Create a CloudFormation stack.

    Args:
        stack_name (str): Name of the CloudFormation stack.
        template_data (str): JSON-formatted CloudFormation template.
        params (list[dict]): List of parameter dictionaries for the CloudFormation stack.

    Returns:
        bool: True if stack creation is successful, False otherwise.
    """
    cfn_client = boto3.client('cloudformation')

    try:
        response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_data,
            Parameters=params,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            DisableRollback=True,
            TimeoutInMinutes=10
        )

        if 'ResponseMetadata' in response and \
                response['ResponseMetadata']['HTTPStatusCode'] < 300:
            stack_id = response['StackId']
            print("Waiting for stack creation.....")
            wait_for_stack_creation(cfn_client, stack_id)
            return True
        else:
            print(
                f"There was an Unexpected error.")
    except botocore.exceptions.ClientError as error:
        print(f"There was an error creating the stack {error}")
    except Exception as error:
        print(f"There was an error creating the stack {error}")


def wait_for_stack_creation(cf_client, stack_id):
    """
    Wait for the CloudFormation stack creation to complete.

    Args:
        cf_client: Boto3 CloudFormation client.
        stack_id (str): ID of the CloudFormation stack.
    """
    while True:
        response = cf_client.describe_stacks(StackName=stack_id)
        stacks = response['Stacks']

        if stacks and stacks[0]['StackStatus'] != 'CREATE_IN_PROGRESS':
            break

        time.sleep(5)


def create_stack_params(cli_args, secret_arn):
    """
    Create the parameters for the CloudFormation stack creation.

    Args:
        cli_args: Command-line arguments parsed by argparse.

    Returns:
        list[dict]: List of parameter dictionaries for the CloudFormation stack.
    """
    with open(cli_args.config) as api_config_file:
        uptycs_api_params = json.load(api_config_file)

    cft_params = [
        {
            "ParameterKey": "UptycsSecretName",
            "ParameterValue": secret_arn,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "ExistingAccounts",
            "ParameterValue": cli_args.existingaccts,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "CloudTrailAccount",
            "ParameterValue": cli_args.ctaccount,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "CloudTrailBucketName",
            "ParameterValue": cli_args.ctbucket,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "CloudTrailBucketRegion",
            "ParameterValue": cli_args.ctregion,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "CloudTrailBucketLogPrefix",
            "ParameterValue": cli_args.ctprefix,
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        }
    ]
    return cft_params

def check_org_trail_exists():
    """
    Create the parameters for the CloudFormation stack creation.

    Args:
       None

    Returns:
        dict: Dictionaries containing org trail data.
    """
    ct_client = boto3.client('cloudtrail')
    try:
        trails = ct_client.describe_trails()
        for trail in trails['trailList']:
            if trail['IncludeGlobalServiceEvents'] == True and trail['IsMultiRegionTrail'] == True:
                return trail
        return None
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InternalError':  # Generic error
            print(f"Error Getting trail data: {error.response['Error']['Message']}")



def main():
    """
    Main function to parse arguments and perform actions on the CloudFormation stack.
    """
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )
    parser.add_argument('--action', choices=['Check', 'Create', 'Delete'], required=True,
                        help='REQUIRED: The action to perform: Check, Create, or Delete')
    parser.add_argument('--config', required=True,
                        help='REQUIRED: The path to your auth config file downloaded '
                             'from Uptycs console')
    parser.add_argument('--ctaccount',
                        help='REQUIRED: Cloudtrail account')
    parser.add_argument('--ctbucket',
                        help='The Name of the CloudTrail bucket')
    parser.add_argument('--ctprefix',
                        help='REQUIRED: The CloudTrail log prefix')
    parser.add_argument('--ctregion',
                        help='REQUIRED: The Name of the CloudTrail bucket region')
    parser.add_argument('--rolename',
                        help='OPTIONAL: The Name of the IAM role that you will create',
                        default='UptycsIntegrationRole')
    parser.add_argument('--permboundary',
                        help='OPTIONAL: Permissions boundary policy to apply to the role',
                        default='')
    parser.add_argument('--existingaccts', choices=['Yes', 'No'],
                        help='OPTIONAL: Apply the Role to existing accounts',
                        default='Yes')
    parser.add_argument('--secretname',
                        help='OPTIONAL: Name of the Uptycs API credentials secret',
                        default='uptycs-cnap-creds')
    args = parser.parse_args()
    action = args.action

    if action == 'Create':
        check_file_open(args.config)
        check_file_open(TEMPLATE_FILE)
        if check_stack_exists(STACK_NAME):
            print(f"\nFound existing CloudFormation stack with Stack Name {STACK_NAME} \n\nYou "
                  f"should rerun the script with --action Delete.\n"
                  f"Please remove any stack instances from the "
                  f"Uptycs-Log-Archive-Integration-StackSet")
            sys.exit()
        if check_apikeys(args.config):
            print("API file looks ok. Writing file to SecretsManager")
            secret_arn = write_json_to_secrets_manager(args.secretname, args.config)
        else:
            print("API keys looks invalid... exiting")
            sys.exit(0)
        cft_params = create_stack_params(args, secret_arn)

        try:
            with open(TEMPLATE_FILE) as template_file:
                template_data = json.load(template_file)
        except FileNotFoundError:
                print(f"File '{TEMPLATE_FILE}' not found.")
        except IOError:
            print(f"Error opening file '{TEMPLATE_FILE}'.")
        create_cft_stack(STACK_NAME, json.dumps(template_data), cft_params)
        print(f"Deleting api config file..../n")
        delete_file(args.config)

    elif action == 'Check':
        print(f"\nChecking for required files....")
        check_file_open(args.config)
        if check_apikeys(args.config):
            print("API file looks ok")
            write_json_to_secrets_manager(args.secretname, args.config)
        else:
            print("API keys looks invalid... exiting")
            sys.exit(0)
        check_file_open(TEMPLATE_FILE)
        print(f"\nChecking for existing setup....\n")
        if check_stack_exists(STACK_NAME):
            print(f"The stack {STACK_NAME} already exists... you should delete the existing stack "
                  f"first ")
        if check_apikeys(args.config):
            print("API file looks ok")
        else:
            print("API keys looks invalid... exiting")
            sys.exit(0)
        trail_data = check_org_trail_exists()
        print(f"\nLooking for a suitable CloudTrail.....")
        if trail_data is not None:
            bucket_data = trail_data['S3BucketName'].split("-")
            region = "-".join(bucket_data[-3:])
            # Trail found, perform actions using the trail data
            print(f"Found an existing org wide trail in this account.....\n")
            print(f"You can use these values for CloudTrail in the script")
            print(f"--ctaccount {bucket_data[3]} "
                  f"--ctbucket {trail_data['S3BucketName']} "
                  f"--ctprefix {trail_data['S3KeyPrefix']} "
                  f"--ctregion {region}")
        else:
            print(f"\nNo org wide trail found in this account. "
                  f"You may have suitable trails already setup. "
                  f"Check the logging account for your CloudTrail configuration")

    # No trail found, handle this case
    # ...



    elif action == 'Delete':
        if check_stack_exists(STACK_NAME):
            delete_stack(STACK_NAME)
        # delete_secret_if_exists(args.secretname)


if __name__ == '__main__':
    main()
