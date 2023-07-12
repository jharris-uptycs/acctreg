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
import argparse
import json
import time
import sys
import boto3
import botocore

TEMPLATE_FILE = "./cloudformation/master-acct.json"
STACK_NAME = 'uptycs-ct-master'


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


def create_cft_stack(stack_name: str, template_data: str, params: list[dict]):
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
            DisableRollback=False,
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


def create_stack_params(cli_args):
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
            "ParameterKey": "UptycsAPIKey",
            "ParameterValue": uptycs_api_params['key'],
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "UptycsSecret",
            "ParameterValue": uptycs_api_params['secret'],
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "UptycsCustomerId",
            "ParameterValue": uptycs_api_params['customerId'],
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "UptycsDomain",
            "ParameterValue": uptycs_api_params['domain'],
            "UsePreviousValue": False,
            "ResolvedValue": "string"
        },
        {
            "ParameterKey": "UptycsDomainSuffix",
            "ParameterValue": uptycs_api_params['domainSuffix'],
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
                        help='The action to perform: Check, Create, or Delete')
    parser.add_argument('--config', required=True,
                        help='REQUIRED: The path to your auth config file downloaded '
                             'from Uptycs console')
    parser.add_argument('--rolename',
                        help='OPTIONAL: The Name of the IAM role that you will create',
                        default='UptycsIntegrationRole')
    parser.add_argument('--ctaccount',
                        help='Cloudtrail account')
    parser.add_argument('--ctbucket',
                        help='The Name of the CloudTrail bucket')
    parser.add_argument('--ctprefix',
                        help='The CloudTrail log prefix')
    parser.add_argument('--ctregion',
                        help='The Name of the CloudTrail bucket region')
    parser.add_argument('--permboundary',
                        help='OPTIONAL: Permissions boundary policy to apply to the role',
                        default='')
    parser.add_argument('--existingaccts', choices=['Yes', 'No'],
                        help='OPTIONAL: Apply the Role to existing accounts',
                        default='Yes')

    args = parser.parse_args()
    action = args.action

    if action == 'Create':
        check_file_open(args.config)
        check_file_open(TEMPLATE_FILE)
        if check_stack_exists(STACK_NAME):
            print(f"\nFound existing CloudFormation stack with Stack Name {STACK_NAME} \n\nYou "
                  f"should rerun the script with --action Delete"
                  f"Please remove any stack instances from the "
                  f"Uptycs-Log-Archive-Integration-StackSet  and  ")
            sys.exit()

        cft_params = create_stack_params(args)

        try:
            with open(TEMPLATE_FILE) as template_file:
                template_data = json.load(template_file)
        except FileNotFoundError:
                print(f"File '{TEMPLATE_FILE}' not found.")
        except IOError:
            print(f"Error opening file '{TEMPLATE_FILE}'.")
        create_cft_stack(STACK_NAME, json.dumps(template_data), cft_params)

    elif action == 'Check':
        print(f"\nChecking for required files....")
        check_file_open(args.config)
        check_file_open(TEMPLATE_FILE)
        print(f"\nChecking for existing setup....")
        if check_stack_exists(STACK_NAME):
            print(f"The stack {STACK_NAME} already exists... you should delete the existing stack "
                  f"first ")

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
            print(f"\nNo org wide trail found in this account \n"
                  f"You may have suitable trails already setup.\n"
                  f"Check the logging account for your CloudTrail configuration")

    # No trail found, handle this case
    # ...



    elif action == 'Delete':
        if check_stack_exists(STACK_NAME):
            delete_stack(STACK_NAME)


if __name__ == '__main__':
    main()
