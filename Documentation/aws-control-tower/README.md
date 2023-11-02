# Uptycs AWS Control Tower Integration

## Prerequisites
You need the following prerequisites to implement the Uptycs AWS Control Tower integration.

- AWS Control Tower with a Landing Zone. For information about setting up an AWS Control Tower landing zone, see [Getting Started with AWS Control Tower in the AWS Control Tower User Guide](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html).
- Administrator privileges in the AWS Control Tower management or delegated account.
- A Uptycs Cloud Security Platform SaaS account.

## Overview
Uptycs delivers a breakdown of your cloud identity risk and governance based on identity types, credentials, activity, and AWS IAM configurations. With Uptycs, security teams are better able to protect your AWS resources from unauthorized access, misuse, and insider threat. Uptycs also provides permission gap analysis and identity mapping to see which assets an identity has access to, which permissions are granted to them, and which are actually being used

https://www.uptycs.com/blog/continuously-monitor-your-cloud-infrastructure-to-improve-cloud-security-posture

## Components
AWS Control Tower provides an integrated solution to set up and govern a secure, multi-account AWS environment. Within Control Tower, landing zones and Account Factory play crucial roles in streamlining the account provisioning and management process. A landing zone serves as a foundation for creating a well-architected, multi-account environment aligned with industry best practices. It establishes a baseline configuration that includes security guardrails, identity and access management policies, network architecture, and logging standards. Landing zones enable organizations to enforce consistent governance and compliance across multiple AWS accounts, facilitating secure and scalable cloud deployments.

Account Factory, on the other hand, complements landing zones by automating the creation and management of AWS accounts at scale. It provides a centralized interface to create new accounts, defining standardized configurations, and applying pre-approved guardrails. This automated process eliminates the manual effort and potential errors involved in setting up individual accounts. Account Factory helps organizations enforce consistent policies, implement security controls, and reduce operational overhead when onboarding new teams or applications. 

Uptycs Customers can now use Account Factory to create accounts and have Uptycs automatically 
integrated into those accounts. 


![control_tower_architecture](./images/overview.png)



### New Account Automation

1. The creation of a new AWS account via Account Factory creates a Control Tower lifecycle event 
   which triggers the EventBridge rule
2. The EventBridge Rule invokes a Lambda function `uptycs-account-handler.py` processes the 
   message and extracts the account id.
4. The uptycs-account-handler.py Lambda creates a new Uptycs-Integration Stack instance for the 
   account.
5. The Stack instance creates a new Uptycs Cloud Integration cross-account role that permits 
   Uptycs to monitor the account via AWS APIs.


When creating AWS organizations, creating AWS accounts or moving AWS accounts across organizations, ensure that you use the [recommended AWS Control Tower methods](https://docs.aws.amazon.com/controltower/latest/userguide/provision-and-manage-accounts.html). This will ensure that Uptycs monitors the correct AWS accounts. Making updates to AWS accounts outside of AWS Control Tower may cause issues.

