import time

import boto3
import argparse
import sys
import boto3
import botocore
import json
import uuid
import urllib
import base64
import datetime
import hmac
import hashlib

api_config_file = 'apikey.json'

UPTYCS_ACCOUNT_ID = '031552911331'
TEMPLATE_FILE = "./cloudformation/member_acct_template.json"
STACK_NAME = 'Uptycs-Integration-test'
UPTYCS_API_PARAMETER_STORE = 'integration-api-keys'

def check_stack_exists(stack_name):
    cf_client = boto3.client('cloudformation')
    try:
        cf_client.describe_stacks(StackName=stack_name)
        return True
    except cf_client.exceptions.ClientError as error:
        if 'does not exist' in str(error):
            return False
        else:
            raise error

def gen_api_headers(key, secret):
    token = create_auth_token(key, secret)
    req_header = {
        'Authorization': f"Bearer {token}",
        'date': datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        'Content-type': "application/json"
    }
    return req_header

def gen_cloudaccounts_api_url(domain, domainSuffix, customer_id):
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloudAccounts"
    return uptycs_api_url


def gen_cloudtrail_api_url(domain, domainSuffix, customer_id):
    uptycs_api_url = f"https://{domain}{domainSuffix}/public/api/customers/{customer_id}/cloudTrailBuckets"
    return uptycs_api_url


def get_uptycs_internal_id(url, req_header, account_id):
    params = {"hideServices": "true", "hideSideQuery": "false", "minimalInfo": "true"}
    status, response = http_get(url, req_header, params)
    for item in response['items']:
        if item['tenantId'] == account_id:
            return item['id']

def account_cloudtrail_handler(api_config_file, bucket_name, bucket_region):
    with open(api_config_file) as api_config_file:
        uptycs_api_params = json.load(api_config_file)
    account_id = get_account_id()
    # uptycs_api_params = get_ssm_parameter(UPTYCS_API_PARAMETER_STORE)
    domain = uptycs_api_params.get('domain')
    domainSuffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    req_header = gen_api_headers(key, secret)
    uptycs_api_url = gen_cloudtrail_api_url(domain, domainSuffix, customer_id)
    response_data = {}
    try:
        req_payload = {
              "tenantId": account_id,
              "bucketName": bucket_name,
              "bucketRegion": bucket_region,
              "bucketPrefix": None
            }
        status, response = http_post(uptycs_api_url, req_header, req_payload)
        if status == 200:
            response = f"Successfully added cloudtrail {account_id}"
            return status, response

        else:
            print('Failed to add cloudtrail ')
            return status, response['error']['message']['detail']
    except Exception as error:
        response(f"Error during create event {error}")
        return status, response

def account_registration_handler(action, api_config_file, role_name, external_id=None):
    with open(api_config_file) as api_config_file:
        uptycs_api_params = json.load(api_config_file)
    account_id = get_account_id()
    # uptycs_api_params = get_ssm_parameter(UPTYCS_API_PARAMETER_STORE)
    domain = uptycs_api_params.get('domain')
    domainSuffix = uptycs_api_params.get('domainSuffix')
    customer_id = uptycs_api_params.get('customerId')
    key = uptycs_api_params.get('key')
    secret = uptycs_api_params.get('secret')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    req_header = gen_api_headers(key, secret)
    uptycs_api_url = gen_cloudaccounts_api_url(domain, domainSuffix, customer_id)

    response_data = {}

    if action == "Create":
            try:
                req_payload = {
                    "tenantId": account_id,
                    "tenantName": account_id,
                    "connectorType": "aws",
                    "cloudformationTemplate": "https://uptycs-integration.s3.amazonaws.com/aws/cf-templates/uptycs_integration-130-020.json",
                    "accessConfig": {
                        "role_arn": role_arn,
                        "external_id": external_id
                    }
                }
                status, response = http_post(uptycs_api_url, req_header, req_payload)
                if status == 200:
                    response = f"Successfully integrated AWS account {account_id}"
                    return status, response

                else:
                    print('Failed to register AWS account ')
                    return status, response['error']['message']['detail']
            except Exception as error:
                response(f"Error during create event {error}")
                return status, response

    # Handle delete event
    elif action == "Delete":
        try:
            uptycs_account_id = get_uptycs_internal_id(uptycs_api_url, req_header, account_id)
            if uptycs_account_id:
                resp = deregister_account(uptycs_api_url, req_header, uptycs_account_id)
                if resp == 'OK':
                    print('Successfully deleted AWS account')
                else:
                    print('Failed to delete AWS account')
            else:
                print(f"Account {account_id} is not registered")
        except Exception as error:
            print(f'Exception {error} deleting AWS account')

    # Handle update event
    elif action == "Update":
        pass

def delete_stack(stack_name):
    cloudformation_client = boto3.client('cloudformation')

    try:
        cloudformation_client.delete_stack(StackName=stack_name)
        print(f"Deleting stack '{stack_name}' initiated.")
    except cloudformation_client.exceptions.ClientError as e:
        print(f"Failed to delete stack '{stack_name}': {e.response['Error']['Message']}")

def create_cft_stack(stack_name: str, template_data: str, params: dict):
    cfn_client = boto3.client('cloudformation')
    """
    Creates a cloudformation stack instance
    """

    try:
        response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_data,
            Parameters=params,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            DisableRollback=False,
            TimeoutInMinutes=2
        )

        # we expect a response, if its missing on non 200 then show response
        if 'ResponseMetadata' in response and \
                response['ResponseMetadata']['HTTPStatusCode'] < 300:
            status = response['ResponseMetadata']['HTTPStatusCode']
            stack_id = response['StackId']
            print("Waiting for stack creation.....")
            wait_for_stack_creation(cfn_client, stack_id)
            response = "** Stack created **"
            return True
        else:
            print(
                f"There was an Unexpected error. response: {json.dumps(response)}")
            return
    except botocore.exceptions.ClientError as error:
        print(error)
        return
    except Exception as error:
        print(f"General Exception: {error}")
        return

def wait_for_stack_creation(cf_client, stack_id):
    while True:
        response = cf_client.describe_stacks(StackName=stack_id)
        stacks = response['Stacks']

        if stacks and stacks[0]['StackStatus'] != 'CREATE_IN_PROGRESS':
            break

        # Wait for a few seconds before checking again
        time.sleep(5)

def gen_external_id():
    return str(uuid.uuid4())

def check_ssm_param_exists(param_name):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.get_parameter(Name=param_name)
        print(f"Parameter '{param_name}' exists.")
        return True
    except ssm_client.exceptions.ParameterNotFound:
        print(f"Parameter '{param_name}' does not exist.")
        return False

def write_dict_to_ssm(secret_name, data):
    ssm_client = boto3.client('ssm')
    response = ssm_client.put_parameter(
        Name=secret_name,
        Value=json.dumps(data),
        Type='SecureString',
        Overwrite=True
    )

def get_account_id():
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    account_id = response['Account']
    return account_id

def check_for_cloudtrail():
    session = boto3.Session()
    # Retrieve the CloudTrail client using the new session
    cloudtrail_client = session.client('cloudtrail')

    # Get the CloudTrail trail information
    response = cloudtrail_client.describe_trails()

    if 'trailList' in response:
        # Assuming there is only one trail, you can modify the code if there are multiple trails
        trail = response['trailList'][0]
        s3_bucket = trail['S3BucketName']
        return(s3_bucket)
    else:
        return

def check_for_existing_role(role_name):
    iam_client = boto3.client('iam')
    try:
        role = iam_client.get_role(RoleName=role_name)
        return True
    except iam_client.exceptions.NoSuchEntityException as error:
        return False

def get_external_id_from_trust_relationship(role_name):
    iam_client = boto3.client('iam')

    try:
        response = iam_client.get_role(RoleName=role_name)
        role = response['Role']
        assume_role_policy = role['AssumeRolePolicyDocument']
        if 'Statement' in assume_role_policy:
            for statement in assume_role_policy['Statement']:
                if 'Condition' in statement and 'StringEquals' in statement['Condition']:
                    conditions = statement['Condition']['StringEquals']
                    if 'sts:ExternalId' in conditions:
                        return conditions['sts:ExternalId']
    except iam_client.exceptions.NoSuchEntityException:
        pass

    return None

def get_ssm_parameter(parameter_name: str, with_decrypt: bool = True) -> object:
    """
    Retrieve a JSON object from an SSM parameter.
    Args:
        parameter_name (str): The name of the SSM parameter.
        with_decrypt (bool): Parameter requires Decryption. Default is True.

    Returns:
        Dict: A dictionary containing the JSON object stored in the SSM parameter.
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=with_decrypt)
    parameter_value = response['Parameter']['Value']
    return json.loads(parameter_value)


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


def http_delete(url, headers):
    req = urllib.request.Request(url, headers=headers, method='DELETE')
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.msg
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))



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


def deregister_account(url, header, account_id):
    deregister_url = f"{url}/{account_id}"
    status, response = http_delete(deregister_url, header)
    if status == 200:
        return (response)



def main():
    """
    Main function to parse arguments and call Uptycs Web API to update External ID and IAM Role ARN in AWS CSPM integration
    """
    parser = argparse.ArgumentParser(
        description='Creates a cloudformation template to Integrate Uptycs with this account'
    )
    parser.add_argument('--action', choices=['Check', 'Create', 'Delete'], required=True,
                        help='The action to perform: Check, Create, or Delete')
    parser.add_argument('--config', required=True,
                        help='REQUIRED: The path to your auth config file downloaded from Uptycs console')
    parser.add_argument('--rolename',
                        help='OPTIONAL: The Name of the IAM role that you will create',
                        default='UptycsIntegrationRole')
    parser.add_argument('--permboundary',
                        help='OPTIONAL: Permissions boundary policy to apply to the role',
                        default='')
    parser.add_argument('--ssmparam',
                        help='OPTIONAL: The Name of the ssm parameter store',
                        default='uptycs_apikey_file')
    parser.add_argument('--ctbucket',
                        help='OPTIONAL: The Name of the CloudTrail bucket')
    parser.add_argument('--ctregion',
                        help='OPTIONAL: The Name of the CloudTrail bucket region')
    parser.add_argument('--accountname',
                        help='OPTIONAL: The name you want to identify this account with on Uptycs console')
    parser.add_argument('--kmsarn',
                        help='OPTIONAL: The KMS Arn if required')

    # Parse the arguments
    args = parser.parse_args()

    action = args.action

    # Access the values of the arguments
    api_config_file = args.config
    rolename = args.rolename
    ssmparam = args.ssmparam
    accountname = args.accountname
    permboundary = args.permboundary
    ctbucket = args.ctbucket
    ctregion = args.ctregion
    kmsarn = args.kmsarn

    # Check if --arn argument is provided
    if accountname is None:
        # Handle the case when --arn argument is not provided
        accountname = get_account_id()

    if action == 'Check':

        print(f"Checking if role {rolename} already exists")
        role_exists = check_for_existing_role(args.rolename)
        if role_exists:
            external_id = get_external_id_from_trust_relationship(rolename)
            print(f"Found and existing role with name {rolename} and externalId {external_id}")
        else:
            print(f"Role {rolename} does not currently exist")

        print(f"Checking if a suitable CloudTrail configuration exists.")
        bucket = check_for_cloudtrail()
        if bucket:
            print(f"Found a valid CloudTrail logging to a bucket {bucket}")
        else:
            print(f"No valid CloudTrail exists")


        if check_ssm_param_exists(ssmparam):
            print(f'The API parameters file {ssmparam} already exists')

        else:
            try:
                with open(args.config) as api_config_file:
                    data = json.load(api_config_file)
                    # write_dict_to_ssm(ssmparam, data)
            except FileNotFoundError:
                print("File not found check the location of the apikey file: ", args.config)
                sys.exit(0)







    if action == 'Delete':
        if check_stack_exists(STACK_NAME):
            delete_stack(STACK_NAME)
        account_registration_handler(action, api_config_file, rolename)

    elif action == 'Create':
        uptycs_account_id = UPTYCS_ACCOUNT_ID
        external_id = gen_external_id()
        uptycs_role_name = rolename
        # Create the Uptycs Read Only Role StackSet for member accounts
        with open(TEMPLATE_FILE) as template_file:
            template_data = json.load(template_file)

        member_acct_params = [
            {
                "ParameterKey": "UptycsAccountId",
                "ParameterValue": uptycs_account_id,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "ExternalId",
                "ParameterValue": external_id,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "UptycsRoleName",
                "ParameterValue": uptycs_role_name,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "PermissionsBoundary",
                "ParameterValue": permboundary,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "CloudTrailBucketName",
                "ParameterValue": ctbucket,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            },
            {
                "ParameterKey": "KMSKeyArn",
                "ParameterValue": kmsarn,
                "UsePreviousValue": False,
                "ResolvedValue": "string"
            }

        ]
        if create_cft_stack(STACK_NAME, json.dumps(template_data), member_acct_params):
            print("Waiting for role to propagate to all regions.....")
            time.sleep(5)
            status, response = account_registration_handler(action, api_config_file, rolename,
                                                      external_id)
            print(response)
            print("Adding Cloudtrail config ...")
            account_cloudtrail_handler(api_config_file, ctbucket, ctregion)


        else:
            print("Failed to create role...exiting")


if __name__ == '__main__':
    main()

