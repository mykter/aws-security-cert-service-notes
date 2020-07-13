# AWS Service Security Notes
An all-in-one-place collection of security information about all of the core AWS services.

These are the notes I created whilst studying for the [AWS Certified Security - Specialty](https://aws.amazon.com/certification/certified-security-specialty/) exam. They are intended as a knowledge check, reminder, and subject list for each AWS service. They are not intended as a primary learning source, and they assume an existing knowledge of security. I think if you can look through this list and feel confident that you are familiar with all of it, don't come away with a lot of follow up questions, and think you can recall most of it unaided, then you will probably pass the security certification exam. It worked for me, anyway!

I don't plan to actively maintain this document as AWS evolves - reader beware, the rate of change at AWS is high! I would like to correct any errors though - please do raise an issue. I'll also happily accept pull requests if you find yourself using it and wish to bring it up to date, or fix errors, or otherwise enhance it in any way.

Final caveat: this doesn't teach you how to be good at AWS security. See my blog post on [what I think the Security Speciality certification means](https://mykter.com/2019/05/04/aws-security-certification), and hence what this document aims to cover.

If you found this useful please [let me know](https://twitter.com/michael_macnair)!

<br><br>
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">AWS Service Security Notes</span> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.<br />Based on a work at <a xmlns:dct="http://purl.org/dc/terms/" href="https://github.com/mykter/aws-security-cert-service-notes" rel="dct:source">https://github.com/mykter/aws-security-cert-service-notes</a>.

# Services
A complete list of the AWS security services, and selected additional AWS services of relevance to security (in particular, the security specialist certification). Taken from the [AWS product list](https://aws.amazon.com/products/) as of March 2019; if a category isn't listed it's because I thought none of the services in that category are particularly applicable.

Particularly important services from an exam perspective are in **bold**.

Security service links are to their FAQ pages, as a useful source of information on particular use cases and constraints that might be examined. Other service links are to their main product pages, but the FAQ pages often have good information including a security section too.

## Security

* [Artifact](https://aws.amazon.com/artifact/faq/)
    + Generic AWS compliance docs

* [Certificate Manager](https://aws.amazon.com/certificate-manager/faqs/)
    + Issuance can take a few hours
    + Email or DNS validation (CloudFormation only supports email validation)
    + Validates DNS CA Authorization records first
    + Certs are region-locked, unless CloudFront is used (w/ Virginia)
    + Private keys are KMS protected - CloudTrail shows services using KMS to get the keys
    * Private CA
        + Allows export of the private key, whereas public standard only integrates with AWS services

* [Cloud Directory](https://aws.amazon.com/cloud-directory/faqs/)
    + Generic directory service - not Active Directory. Could be used for user/device management.
    + Encrypted at rest and in transit

* [CloudHSM](https://aws.amazon.com/cloudhsm/faqs/)
    + Advertised as only suitable when you have contractual/regulatory constraints.
    + Only option for SQL Server and Oracle transparent database encryption (but not AWS RDS Oracle! only instances running on EC2. RDS Oracle  only works with CloudHSM Classic). Also works with Redshift.
    + PKCS#11, JCE, CNG
    + FIPS 140-2 Level 3 certified
    + KMS can use it as a key store - see KMS section
    + Each instance appears as network resource in VPC; client does load-balancing.
    + [[HSM] Server] <-TLS-in-TLS-> [client] <-p11 etc-> [app]
    + HSM users authenticate with username + password
    + CloudTrail for provisioning API calls; CloudWatch Logs for HSM logs

* [**Cognito**](https://aws.amazon.com/cognito/faqs/)
    * User Pools
        + Free up to 50k monthly active users
        + OAuth user tokens
    * Identity Pools
        + Mapping between federated user IDs and Cognito user IDs. Per pool.
        + Grants temporary AWS creds (either directly from federation, or in exchange for a user pool token)
        + IAM Roles assigned based on: mappings defined for a user pool group / rules / guest
    + API Gateway has direct support for Cognito tokens (no need for identity pool)
    + Sync store - key/value store per identity
    + [Common scenarios](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-scenarios.html)
    + Various soft limits e.g. API calls/s, groups/pool, etc. No limit on number of users.

* [**Directory Service**](https://aws.amazon.com/directoryservice/faqs/)
    + Works with EC2 (manage them via group policies), RDS SQL server, WorkSpaces, AWS SSO, and a few more obscure ones
    + Can assign IAM roles to AD users for AWS access
    * Managed Microsoft AD
        + Can join to existing AD with trust relationships
        + Or replace an on-prem AD by using Direct Connect or VPN
        + EBS volumes are encrypted. Deployed on two AZs. Daily backups.
        + Some high-priv operations not available. No remote access or powershell access. You get an OU and delegated admin account for it.
    * AD Connector
        + Proxy for [a specific list of AWS services](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_connector_app_compatibility.html) through to on-prem AD.
        + Notably works with: SSO; management console; EC2 Windows (join domain)
    * Simple AD
        + Samba backend. Like Managed Microsoft AD but less features and smaller resource limits.

* [Firewall Manager](https://aws.amazon.com/firewall-manager/faqs/)
    + Centrally manage WAF rules across CloudFront and ELB Application Load Balancers via Organizations
    + (not NACLs or Security Groups)

* [**Guard Duty**](https://aws.amazon.com/guardduty/faqs/)
    + Uses CloudTrail, VPC Flow Logs, and DNS Logs (if EC2 instances are configured to use Route 53 resolvers - the default). Doesn't require you to enable them!
    + ^^ meta-data, + AWS' threat intelligence - domains & ips, + ML
    + Pricing per volume of data analyzed
    + Looks for reconnaissance, (ec2?) instance compromise, account compromise
    + Findings -> GuardDuty console (for 90 days) + CloudWatch Events. Findings in JSON format similar to Macie & Inspector
    + Regional. Can aggregate via CloudWatch Events to push to a central store
    + CloudWatch events -> SNS topic (-> email) / Lambda (->S3)

* [**IAM**](https://aws.amazon.com/iam/faqs/)
    * Users, Groups, Roles
        + Roles for EC2 instances
            + creds found in http://169.254.169.254/latest/meta-data/iam/security-credentials/<role / instance profile name>
            + To launch an instance, users need iam:PassRole for the relevant roles.
            + Can be attached at launch or later.
            + Auto rotation, built in support for obtaining the creds when using CLI & SDKs
        + Service linked role - predefined policy granting service what it needs; immutable trust policy.
        + Role trust policy: what principals (account/user/role/service/federated user) can sts:AssumeRole. IAM users/roles also need an identity policy that allow them to assume the role.
        + Assumed role ARN: `arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name`, where the session name might be the EC2 instance ID, or the IAM username, for example.
    * Access keys
        + Rotate by creating second access key, start using it, check last used date of old one, make old one inactive, then delete it
        + Trusted advisor can look for overly long-lived access keys
    * Policies
        + Resource based policies
            + Specifies a Principal.
            + Can't be managed policies - always inline.
            + Not actually IAM policies at all - just usually use the same policy language
            + Notable ones: Organizations (SCP); S3; API Gateway; Lambda; KMS 
        + Identity based policies (aka IAM policies)
            + Attached to a user/group/role - implicit Principal
            + Limit of 10 managed policies can be attached
            + Versions - up to 5, you set which is the 'default' for customer managed policies. Inline policies don't have versions.
        * [Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
            + Set the maximum permissions that an identity-based policy can grant to an IAM entity
            + Unlike SCPs, can specify resources and use conditions
        + Service Control Policies (SCPs) - see Organizations
        + Session policies - like a permission boundary, optionally passed programatically as part of AssumeRole*
        * [Evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) - but there are special cases not listed here, e.g. KMS, S3
        * Conditions
            * Operators
                + Date, Numeric, String, Bool, Binary (b64), IpAddress, Arn, Null (key:true - key doesn't exist, key:false - key does exist and isn't null)
                + operators are ANDed, multiple values in an operator are ORed
                + ...IfExists returns true if key doesn't exist
                + Set operators for keys with multiple values - ForAllValues:<operator>... ForAnyValue:<operator>...
            + All services: time, MFA, secure transport, user agent
            + aws:source{Vpc,Vpce (endpoint),Account,Arn,Ip}
            + aws:PrincipalOrgID - instead of listing lots of accounts, just use the Org. In resource policies - Principal:*, then this condition
            + aws:PrincipalTag/<tag-key> - you can tag users and roles. Also service:ResourceTag and aws:RequestTag (control what tags users can use when tagging resources).
            + aws:PrincipalType
            + aws:RequestedRegion
            + aws:userid aws:username
        * Policy variables
            + Use in resource element and string operators in conditions
            + Basically the same set of variables as global conditions. aws:username etc.
        * (Not)Principal
            + AWS - users, roles, accounts
            + Federated - just "this principal authenticated with this provider" - no info on the role
            + Service - in trust policies
            + AWS:* - IAM identities (not services)
            + NotPrincipal rarely, and not with Allow as v fragile. NotPrincipal+Deny acts like a whitelist due to policy eval rules.
        + NotAction - matches everything except the list of actions. With Allow is very broad - combine with a resource constraint to make it more selective.
        * Resource
            + Wildcards - *? - don't span segments
            + NotResource + Deny: blacklist. NotResource + Allow: risky - allows all others incl. future ones.
    * Access advisor
        + When did an entity last use a permission
        + For each of User, Group, Role, and Policy
    * Federation
        + SAML
            + Users gets SAML assertion from their IdP portal, uses STS to exchange it for temporary creds.
            + IdP maps users/groups to roles.
            + Requires config info including keys registered with both the IdP and AWS IAM
            + Use AWS SSO to access the console.
        + Web identity federation - just use Cognito. IAM does support it natively too though.
        + Active Directory - use Directory Service, setup roles that trust DS, assign users or groups to roles
    + [Service support](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html)
        + Of interest are services that have resource-based policies, services that don't have resource-level permissions, and services that don't support temporary creds
        + Notable resource-based policies: ECR; Lambda; S3 & Glacier; KMS; Secrets Manager; API Gateway; VPC endpoints; SNS; SQS; SES
        + Notable ones missing resource level permissions: CloudFront (no resource policies either)
        + ~everything that matters supports temporary credentials
    * Temporary credentials
        + Can't be revoked, but you can revoke an IAM user if they created the temporary creds, which invalidates them.
        + Include a token as well as access key & secret key. Token is appended to requests (header/query param)
        + Not regional
        + You can use AssumeRoleWithWebidentity as a less-featured alternative to Cognito w/ your users
    * Multifactor
        + No support for SMS any more.
        + U2F, virtual TOTP, hardware TOTP provided by AWS.
        + Root user can recover from lost second factor by verifying email address + phone number ownership.
        + APIs can require it by adding condition statements to identity or resource policies using `aws:MultiFactorAuthPresent` or `aws:MultiFactorAuthAge` (time since factor seen). Users then call STS to get temporary credentials that allow them to use the API. Doesn't work with root or U2f.
        + Doesn't work with federation

* [Inspector](https://aws.amazon.com/inspector/faqs/)
    * Rules packages
        + Predefined only.
        + Network: Network Reachability
        + Host: CVEs; CIS Benchmarks; Security Best Practices (OS config incl remote access); Runtime Behavior Analysis (protocols, ports, software config)
    * Template
        + Rules packages (predefined only), target EC2 instances, SNS topic
    + Network reachability + host config (CVEs in package manager installed software, CIS benchmarks for popular OSes)
    * Agent required for host config
    + Network reachability: enumerates what ports are accessible from outside of a VPC (+ what process listening on those ports, with agents)
    + Service linked role to enumerate EC2 instances and network config
    + Simple schedule in template, or more advanced via CloudWatch events / custom use of API

* [**KMS**](https://aws.amazon.com/kms/faqs/)
    * Key policies
        + Required. Also different evaluation logic to standard IAM - if the key policy doesn't allow, then the request is denied regardless of identity policies.
        + Resource: "*" - this CMK
        + Principal: accounts/users/roles/services. Not groups! Have to use IAM identity policies to manage access via groups (or group -> assumerole).
        + Default policy for API-created CMKs allows `kms:*` for the account / root user. This ensure it doesn't become unmanageable, and also _enables_ identity based IAM policies - without it IAM policies are ineffective.
        + Default policy for console created keys also allows you to specify:
            + Roles/Users who are Key Administrators, who can manage it - incl change its policy.
            + Roles/Users/other AWS accounts who are Key Users. They can encrypt/decrypt/generatedatakey, and manage grants for AWS services using the `kms:GrantIsForAWSResource` condition.
    + IAM/identity policies
        + Required for non-key specific tasks list ListKeys, ListAliases, and CreateKey
        + Required to use the console
    + Bunch of [KMS-specific condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html?shortFooter=true#conditions-kms) that can be used in either policy type.
        + `kms:ViaService` to prevent direct API use or block specific service use. All AWS managed CMKs use it to restrict access to the creating service.
    * Grants
        + Another resource-based policy attached to keys.
        + Allow-only, no Deny.
        + "grantee principal" - who can use the CMK. 
        + "retiring principal" - who can revoke the grant
        + Actions: drawn from using the key, and creating further grants
        + Grant tokens: passed back when creating a grant, allows grantees to use the grant even before it has fully propagated. Not secret, no security impact, just practical.
    + Key usage -> CloudTrail
    + AWS services use wrapped data keys with KMS - 'envelope encryption'
    + APIs expose raw encrypt/decrypt operations, <4kb
    * CMKs
        + AES-256
        + CMKs are stored in HSMs (140-2 level 2)
        + AWS managed CMKs you have no control over. Customer managed ones you can set policies.
        + Imported CMKs can be deleted immediately and can have an expiry time.
        + 1000 CMKs per region
        + Keys are region-specific. For a [multi-region solution](https://aws.amazon.com/blogs/security/how-to-use-the-new-aws-encryption-sdk-to-simplify-data-encryption-and-improve-application-availability/), encrypt a single data key under CMKs in different regions.
        + Customer controlled CMKs can be enabled/disabled
        + Automatic annual key rotation can be enabled for customer controlled keys that don't use imported key material.
    * Custom key store
        + Uses CloudHSM
        + Can't import or automatically rotate keys - otherwise the same management as normal key stores
        + Only for customer managed CMKs
        + You're responsible for availability
        + Manual rotation: create key and remap key alias
    * CloudHSM
        + Single tenant 140-2 level 3 HSM - compliance
        + CloudHSMs appear in a VPC
        + Audit options beyond CloudTrail - CloudHSMs log locally and copy to CloudWatch
        + PKCS11 etc interfaces (as well as using as a custom key store)
    + Each region has a FIPS 140-2 validated endpoint (uses openssl fips module) and a standard endpoint. 
    + AES-128 or AES-256 data keys
    + Crypto operations accept an optional _encryption context_, which is used as additional authenticated data (AAD) in the operation. If differs then decryption fails. Included in CloudTrail logs. Example used by S3:
        ```json
        "encryptionContext": {
            "aws:s3:arn": "arn:aws:s3:::bucket_name/file_name"
        },
        ```

* [Macie](https://aws.amazon.com/macie/faq/)
    + Classifies data in S3.
    + Personally Identifiable Information (PII), Personal Health Information (PHI), regulatory documents (legal, financial), API keys and secret key material
    + Watches policy and ACL changes
    + Watches access patterns via CloudTrail
    + Alerts on CloudWatch Events, Lambda, and Macie dashboard
    + Primarily English

* [**Organizations**](https://aws.amazon.com/organizations/faqs/)
    + Organizational Units (OUs) divide up the 'administrative root'
    + Accounts can only be in one OU, and OUs can only be in one OU. But they can be nested up to 5 levels.
    * Service Control Policies (SCPs)
        + Which IAM policy Actions can be used in the account.
        + Applied to the root, to an OU, or to an account
        + Implicit and explicit Deny.
        + All statements: Version, Statement, Sid, Action, and Effect:Allow/Deny
        + Allow statements: no conditions, Resources must be '*'
        + Deny statements: support conditions and resources and NotAction
        + No principal - implicitly the accounts it's applied to
        + Is a whitelist, but can simulate a blacklist with Allow Action:'*' and another Deny statement
        + FullAWSAccess (allow *) is automatically attached to the root and new OUs. You can remove it.
        + Use policy simulator in member accounts to test effect
    * Trusted access
        + service-linked roles get created in member accounts as needed. Authorized via master account.
        + CloudTrail can create an [organizational trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html), for all events in all member accounts. Member accounts can't modify it.
    + Landing Zone account structures, incl logging & security accounts

* [Secrets manager](https://aws.amazon.com/secrets-manager/faqs/)
    + Also see: Systems Manager Parameter Store - no rotation features, but free.
    + Automatic rotation for AWS RDS, DocumentDB, Redshift
    + Lambda functions to rotate other types
    + 4kb limit on secrets (JSON docs)
    + Encryption at rest via KMS. (for cross-account access to a secret, must use a custom CMK that the principal in the other account can use)
    * [Policies](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html)
        + Resource-based (action+principal) and identity-based (action+resource) policies.
        + `arn:aws:secretsmanager:<region>:<account-id>:secret:optional-path/secret-name-6-random-characters`
        + ```json
            {
                "Sid" : "Get current TestEnv secrets",  
                "Effect": "Allow",
                "Action": [ "secretsmanager:GetSecretValue" ],
                "Resource": "arn:aws:secretsmanager:<region>:<account_id>:secret:TestEnv/*",
                "Condition" : { 
                    "ForAnyValue:StringLike" : {
                        "secretsmanager:VersionStage" : "AWSCURRENT" 
                    } 
                }
            }```
        + Condition keys include `secretsmanager:ResourceTag/<tagname>`, `secretsmanager:VersionStage`
        + Configuring rotation requires creating and assigning a role to a Lambda function, which needs e.g. IAMFullAccess

* [Security hub](https://aws.amazon.com/security-hub/faqs/)
    + Regional - findings don't cross regions
    + Multi-account support
    + Findings from Guard Duty, Inspector, Macie, third party, and self-generated against CIS standards
    + Insights: collections / filters of findings

* [Shield](https://aws.amazon.com/shield/faqs/)
    + Standard - integrated into existing services. Not a stand-alone service. Netflow monitoring & TCP/UDP protection.
    * Advanced
        + Layer 7 protection, WAF rule creation
        + CloudFront integration - can protect non-AWS origins
        + CloudWatch metrics notifications of attacks
        + Global threat environment dashboard, see overall stats for the whole of AWS
        + AWS DDoS team support

* [SSO](https://aws.amazon.com/single-sign-on/faqs/)
    + Free
    + Primary use case: manage multi-account access with Organizations.
    + Additional use case: SSO to other applications via SAML 2 (custom or a bunch of built-in integrations)
    + IAM identity provider created in member accounts for SSO. Also service-linked roles created to allow SSO to manage Roles
    + Sign-ins logged to CloudTrail
    * Directories
        + Native directory - default. Create users & groups within SSO
        + AWS Directory Service - Managed AD & AD Connector (not simple AD)
        + Only a single directory can be connected
    * Permissions sets
        + collections of policies.
        + Implemented as Roles in member accounts.
        + Limit of 20 per account.
        + Ref 10 AWS managed policies, or use an inline policy
    + Control access by mapping users/groups (from the attached directory) to permissions sets & accounts. This data is held in SSO, not the directory.
    + No API!
    + For CLI access, SSO user portal gives you temporary creds for the Roles you have access to

* [WAF](https://aws.amazon.com/waf/faqs/)
    * Conditions
        + Inspect: IP addresses (+ region mapping), HTTP headers, HTTP body, URI strings
        + Match against: SQL injection, cross-site scripting, regex, strings, IP ranges, regions, sizes.
    * Rules
        + Comprise a number of conditions ANDed together
        + Rate based rule - 5 minute period for given IP, e.g. to protect against DDoS or login brute forcing
        + Need conditions for normal rules, but they're optional for rate-based rules (no condition=all requests count)
        + Managed rules from Marketplace sellers.
    * Web ACLs
        + Collection of rules, ORed together
        + Actions per rule: allow, block, or count (for testing)
        + Default action if no rule matches
    + Associate Web ACLs with CloudFront, ALB, and API Gateway instances which will then proxy requests via WAF and act on result
    + Also see Firewall Manager and Shield (Advanced)

## Analytics
(mostly of interest for their application to logs)

* [Athena](https://aws.amazon.com/athena/faqs/)
    + SQL queries over data in S3 after you define a schema. Including (optionally compressed) JSON & CSV
    + Integrates with Glue's Data Catalog - a more featureful version of Athena's built in Data Catalog which supports fine-grained permissions.
    + Charged per query (volume of data scanned)
    + Security model uses both athena:* permissions for queries and data models, and then the underlying S3 permissions
    + Can query encrypted data that uses S3 or KMS managed keys. Can encrypt results.
    + Athena is better than Redshift for querying smaller datasets without pre-processing.
    + CloudTrail can automatically create Athena tables for you, and AWS are keen to push Athena as an ideal CloudTrail analysis tool. Other good candidates: VPC flow logs (if sent to S3), CloudFront, ELB.

* [Elasticsearch service](https://aws.amazon.com/elasticsearch-service/faqs/)
    + IAM auth for management, ES APIs, and resource-based policies down to index level
    + Resource based policies can allow specific IP addresses
    + Kibana auth via Cognito
    + Can configure public or VPC endpoints
    + Ingress via Kinesis Firehose, Logstash, or ES's index/bulk APIs
    + KMS integration for data at rest

* [Glue](https://aws.amazon.com/glue/faqs/)
    + "Select a data source and data target. AWS Glue will generate ETL code in Scala or Python to Extract data from the source, Transform the data to match the target schema, and Load it into the target. "
    + Sources: S3, Redshift, and RDS and other databases
    + Loading into other services for querying (e.g. Athena, Redshift)

* [Kinesis](https://aws.amazon.com/kinesis/)
    + Ingest and analyse various data sources, notably logs
    * [Data Firehose](https://aws.amazon.com/kinesis/data-firehose/faqs/)
        + "capture, transform, and load streaming data into Amazon S3, Amazon Redshift, Amazon Elasticsearch Service, and Splunk"
        + Create delivery stream, with optional Lambda function to transform the data
        + Configure producers to send data to Kinesis with the Kinesis Agent (which monitors log files) or Firehose API
        + Source integrations: CloudWatch Logs subscription filter; CloudWatch Events rule with Firehose target; Kinesis Data Streams. 
        + Configure an IAM role that it assumes to access e.g. S3 or Elasticsearch
        + Manage delivery frequency with buffer size or interval

* Redshift (see Database section)

## Application Integration

* [SNS](https://aws.amazon.com/sns/)
    + Pub/sub.
    + Sources include: SNS API, Lambda, ELB, S3, databases, Code*, CloudWatch, Inspector, and others
    + Destinations: Lambda, SQS, webhooks, SMS, email 
    + Subscribers have to validate - a challenge message is first sent

* [SQS](https://aws.amazon.com/sqs/)
    + Polling, vs SNS's push mechanism
    + Standard queues might reorder messages or deliver them multiple times
    + Has its own resource-based security policy, that predates IAM? Looks similar to IAM policies. Only resource is a queue.
    + Can subscribe to SNS topics
    + Can trigger Lambda functions on message receipt
    + Uses KMS for optional encryption

## Compute

* [**EC2**](https://aws.amazon.com/ec2/)
    * AMIs
        + LaunchPermission attribute - which _accounts_ can use the AMI.
    * [Keypairs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)
        + Create or import - 2k RSA.
        + Independent of instances, but each instance is associated with 1+ keys
        + Linux: it's just an SSH key
        + Windows: upload the private key to the ec2 console to decrypt the default admin password so you can RDP in...
        + Subsequent management: tinker with the `authorized_keys` file
    + [Resources and condition keys](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policy-structure.html)
    + Instance store - hard disk attached to the instance; reset when the instance is stopped. Not encrypted - could use host software disk encryption for a temporary data partition.
    + Instance profile - credentials for a role available to the instance (see IAM section)

* [Elastic Container Registry (ECR)](https://aws.amazon.com/ecr/)
    + IAM access control for pulling & pushing images - identity & resource based
    + Repository policies - e.g. to allow other accounts to pull
    + Images encrypted at rest by default with S3 SSE; HTTPS access

* [Elastic Container Service (ECS)](https://aws.amazon.com/ecs/)
    + Tasks: set of containers that are placed together.
    + Containers run on customer-controlled EC2 instances in a VPC, or are Fargate managed.
    + Networking options:
        + none
        + bridge - docker's virtual network
        + host - tasks get the host's network interface
        + awsvpc: Task network interfaces are normal ENIs so all the VPC properties apply: exist in a subnet, have security groups, have flow logs. Also means each container can have its own security group & IP, vs host networking where all the containers on one host share interfaces.
    + Tasks are configured with an execution role they use to access services
    + Can send logs to CloudWatch
    * [Fargate](https://aws.amazon.com/fargate/) launch type
        + Must use awsvpc network mode, CloudWatch logs
        + Uses [Firecracker](https://firecracker-microvm.github.io/) under the hood (definitely not in scope of the exam, but an interesting topic!)

* [Lightsail](https://aws.amazon.com/lightsail/)
    + Like an entirely separate cloud offering within AWS, with extremely limited features. DigitalOcean competitor.
    + No VPC - separate management of exposed ports
    + Hopefully not in the exam :)

* [Elastic Beanstalk](https://aws.amazon.com/elasticbeanstalk/)
    + Management wrapper around EC2, S3, EBS, RDS
    + Publicly available by default - configure to use a VPC to limit access
    + Beanstalk service role to manage other services. Instance profile - role used by instances to get the app, write logs, etc
    + Logs stored locally, can be configured to use CloudWatch Logs

* Fargate - see ECS

* [**Lambda**](https://aws.amazon.com/lambda/)
    + Logs to CloudWatch
    + Execution role
        + assumed to run
        + at minimum CloudWatch logs creategroup/createstream/putevents
        + Potentially also XRay write, SQS/Kinesis/dynamodb read to get the event data
    + Resource policies
        + Resources: functions, their versions and aliases, and layer versions
            + `arn:aws:lambda:region:123456789012:function:my-function`
            + `arn:aws:lambda:region:123456789012:function:my-function:1`    - version
            + `arn:aws:lambda:region:123456789012:function:my-function:TEST` - alias
        + Use to give other services (principal: service: sns.ama...) and other accounts (principal: aws: account-arn) permission to use them
        + The console updates function policies automatically when you add a trigger to give the triggering service access
    * Identity policies
        + nice examples: ARN pattern so users have to include their username in function names; have to include a logging layer
        + To give users the ability to create functions with limited permissions, constrain what roles they can iam:PassRole on.
        + To give users the ability to add resource permissions to functions so they can be invoked, but only from specific sources, check lambda:Principal in a condition
    * VPC access
        + Can access resources in a VPC if subnet + security group is specified.
        + No internet access unless there is a NAT in the VPC.
        + No AWS service access unless there is internet access or VPC gateways
        + Role needs ability to create network interfaces in each subnet (and VPC must have ENI capacity & subnets must have spare IPs)

* [Elastic Load Balancing (ELB)](https://aws.amazon.com/elasticloadbalancing/)
    + Integrated with Certificate Manager to terminate TLS. Can also upload certs to IAM and configure ELB to use them from there.
    + Can specify which of several predefined cipher-suites - 'security policies' - to support 
    * Application Load Balancer (ALB) - HTTP/HTTPS
        + In a security group
        + Integrated with WAF
        + Authentication: integrates with Cognito and supports Open ID Connect. Redirects users to IdP authorization endpoint, then adds headers with signed JWT containing user info.
        + Can have a Lambda function as a target. Transforms JSON response to HTTP. Function policy needs to allow `elasticloadbalancing.amazonaws.com` to InvokeFunction
        + Can enable access logging to an S3 bucket
    * Network Load Balancer - TCP/TLS
        + Doesn't support Server Name Indication (SNI)
        + 2k RSA certs only (ALB is more flexible)
        + Creates a (read only) network interface in a subnet in each AZ you choose. Not in a security group - instance security groups must allow traffic from its IP address and from client IP addresses
    * (Classic)
    + Logs to S3

## Customer Engagement

* [Simple Email Service (SES)](https://aws.amazon.com/ses/)
    + potentially incident notification, but SNS probably more appropriate
    + Can receive mail, which can be encrypted using a KMS protected key. SDK available to support decryption.
    + TLS API or TLS SMTP connection (port 587), also supports STARTLS and DKIM, and can work with SPF and DMARC

## Database

A comparison and summary of some of the security aspects of the various database offerings:

| **Database** | **Transport encryption**                                                               | **Encryption at rest**                           | **Audit**                                            | **DB Authentication**                                                                                         | **DB Authorization**                                                         |
|--------------|----------------------------------------------------------------------------------------|--------------------------------------------------|------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| RDS          | Rooted at global RDS certs, configuration is per-engine <br>[docs][rds-tls]            | KMS; TDE w/ SQL Server and Oracle - RDS managed key (used to be CloudHSM Classic)| per-engine log files | per engine user accounts - SQL                                                                              | per engine - SQL                                                             |
| DynamoDB     | Standard AWS HTTPS endpoint                                                            | KMS                                              | CloudTrail, excl. Get/Put <br>[docs][dynamodb-audit] | IAM only. Cognito possible. <br>[docs][dynamodb-cognito]                                                      | IAM identity policies - resources & condition keys <br>[docs][dynamodb-auth] |
| Redshift     | ACM managed certificate, redshift specific root <br>[docs][redshift-tls]               | KMS; CloudHSM Classic                            | S3 <br>[docs][redshift-audit]                        | DB user accounts - SQL; IAM with custom drivers <br>[docs][redshift-auth]                                     | SQL                                                                          |
| Neptune      | Publicly trusted Amazon root; mandated for some regions <br>[docs][neptune-tls]        | KMS                                              | Console <br>[docs][neptune-audit]                    | User accounts; or a limited IAM identity policy mechanism + request signing <br>[docs][neptune-auth]          | Engine-specific; or broad access if using IAM                                |
| Aurora       | Rooted at global RDS certs, configuration as per mysql/postgres <br>[docs][aurora-tls] | KMS                                              | mysql -> CloudWatch Logs <br>[docs][aurora-audit]    | User accounts; or an IAM authenticated API to obtain short lived passwords to connect <br>[docs][aurora-auth] | mysql/postgres - SQL                                                         |
| DocumentDB   | Rooted at global RDS certs, configuration as per MongoDB <br>[docs][documentdb-tls]    | KMS                                              | CloudWatch Logs <br>[docs][documentdb-audit]         | MongoDB user accounts                                                                                         | MongoDB standard                                                             |

[rds-tls]: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
[dynamodb-audit]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
[dynamodb-auth]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/using-identity-based-policies.html
[dynamodb-cognito]: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WIF.html
[redshift-tls]: https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html
[redshift-audit]: https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html
[redshift-auth]: https://docs.aws.amazon.com/redshift/latest/mgmt/generating-user-credentials.html
[neptune-tls]: https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html
[neptune-audit]: https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html
[neptune-auth]: https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
[aurora-tls]: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.SSL.html
[aurora-audit]: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Integrating.CloudWatch.html
[aurora-auth]: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.html
[documentdb-tls]: https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html
[documentdb-audit]: https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html


* [DynamoDB](https://aws.amazon.com/dynamodb/)
    + Optional encryption at rest integrated with KMS
    + Main resource is a table. No resource based policies. Full access to a table requires access to not just the `table/<name>` resource, but also `table/<name>/*`
    + Some predefined policies: `AmazonDynamoDBReadOnlyAccess`, `AmazonDynamoDBFullAccess` - custom policies with resource constraints are better
    + Several condition keys for fine-grained access including: `dynamodb:LeadingKeys`, `dynamodb:Select`, `dynamodb:Attributes`
    + Example fine-grained permission: you can only access items where the partition key matches your own (web identity) user ID, by using LeadingKeys and a substitution variable.
    + Get and Put API calls are not logged to CloudTrail - management things are like describe, list, update, create
    + Has a VPC endpoint you can use
    + Integration with Cognito: identity pool with roles configured; roles have appropriate policy to (a) allow cognito to assume them and (b) perform desired DynamoDB actions.

* [RDS](https://aws.amazon.com/rds/)
    + IAM controls database instances. Each instance type has its own permission model for managing the database - a master user is created with the instance.
    + Lots of different resources. The main one is an instance - `db` in the arn. No resource based policies.
    + 'RDS Encryption' - encryption at rest, set during creation, uses KMS. Covers database, backups, replicas, snapshots.
    + Transparent data encryption for SQL Server and Oracle with CloudHSM
    + There's a single root for all RDS database TLS certs; each engine uses its own method for connecting over TLS
    + Manifests as network interfaces in subnets with security groups attached to the interfaces. You specifc a "db subnet group" - a collection of subnets which it can use to put interfaces in.
    + "Publicly accessible" option controls whether there is a publicly resolvable DNS name for the instance. Still needs appropriate security group rules.

* [Redshift](https://aws.amazon.com/redshift/)
    + Cluster management with IAM.
    + Database user accounts for DB permissions (SQL).
    + With custom Amazon Redshift JDBC or ODBC drivers, you can authenticate via IAM and get temporary DB user creds. Gives access to existing users or creates new users (groups specified via claims).
    + Lots of resources, main one is a cluster. No resource based policies. Managed policies to give access to all resources - `AmazonRedshiftFullAccess` and `AmazonRedshiftReadOnlyAccess`
    + Cluster are associated with 1+ security groups. Doesn't appear as an interface in a subnet. Contrast with RDS and DynamoDB - all different combos of network access control.
    + Audit logs, disabled by default, -> S3 (as well as the standard CloudTrail logs). Bucket policy has to allow putobject and getacl to a specific user from a redshift AWS account that varies by region: `arn:aws:iam::<redshift regional account id>:user/logs`. If creating the bucket via the console, it does that for you.
    + Optional encryption at rest. With KMS or CloudHSM Classic (only). Big symmetric encryption key heirarchy.

* [Neptune](https://aws.amazon.com/neptune)
    + HTTPS access
    + Encryption at rest with KMS
    + Interface appears in at least two subnets spanning two AZs in a VPC, interfaces have security groups.
    + CloudTrail events appear as though they are from the RDS service not Neptune - it shares some underlying management infrastructure.
    + Optional audit logs, view or download from the console (no other service integrations, strangely)
    + IAM for management. Permissions are a subset of rds permissions all the actions are `rds` actions. Can constrain to just neptune with a condition of `rds:DatabaseEngine = graphdb`
    + Has a very unique hybrid model where you can authenticate with IAM, and define identity policies that allow access. Limited - no condition keys, no fine grained access (only a single `neptune-db:*` action). Pretty confusing when compared to the previous point. HTTP requests then need to be signed with standard AWS v4 signatures that you construct yourself.

* [Aurora](https://aws.amazon.com/rds/aurora/)
    + The same as the other RDS engines, except:
    + Supports IAM database authentication, similar to Neptune. Attach identity policy to IAM principals that allow `rds-db:connect` for a resource that is a particular database user you create in particular way in the DB. You manage user permissions within the DB as per normal - IAM is just for authentication. You get a 'token' from the RDS API by specifying the db and user, then use the token in place of the user's password when connecting normally.
    + Uses normal VPC security groups to control access within a VPC. Has its own 'DB security group' to control access from outside the VPC - either security groups in other VPCs/accounts or the internet? The other RDS engines only use DB security groups in EC2 classic when a VPC isn't available.

* [DocumentDB](https://aws.amazon.com/documentdb/)
    + Similar to RDS: TLS from the RDS root; KMS encryption at rest; master user + mongodb user mgmt; IAM identity policies for management; VPC security groups; endpoints on multiple subnets/AZs; cloudtrail
    + arns follow the RDS format
    + Auditing can be enabled to send events to CloudWatch Logs. Categories: connection, data definition language (DDL), user management, and authorization

## Developer tools

* [Code Pipeline](https://aws.amazon.com/codepipeline/)
    + Resource-level permissions for pipelines, and their stages and actions.
    + Can integrate with GitHub via OAuth
    + CloudWatch Events for pipeline state changes - started, failed, etc.
    + Supports interface VPC endpoint
    + Trigger from, e.g.: CloudWatch Events (many options, e.g. S3 bucket upload, schedule), webhooks (e.g. github), manual
    + Deploy to, e.g.: CloudFormation, S3, ECS, Service Catalog

## End User Computing

* [WorkSpaces](https://aws.amazon.com/workspaces/)
    + Supports EBS volume encryption for both root and user volumes
    + CloudWatch Event on user login
    + Uses AWS Directory Service for user authentication, works with any of Managed AD, AD Connector, and Simple
    + Can require Mac and Windows clients to use a certificate to authenticate a device to connect
    + WorkSpace network interfaces are associated with a standard VPC security group
    + Has some form of MFA support

## Internet of Things
These sound like they should be in scope, but I suspect they're not as they're very niche.

* IoT Device Defender
* IoT Device Management

## Management and Governance

* [CloudFormation](https://aws.amazon.com/cloudformation/)
    * Stacks
        + You can assign a service role, if you can iam:PassRole it. Anyone who can operate on that stack can leverage that role's permissions (even if they can't run it - they could modify it then someone else runs it!).
        + Otherwise the user/role that is using the stack needs to have permission to perform all the operations
    * StackSets
        + Custom administration role, with identity policies that constrain iam:PassRole for that role to control who can use it
        + Custom execution role, with limits on what resources it has action to, and a trust policy for specific administration role(s) in the admin account
    + Some interesting condition keys:
        + `cloudformation:ChangeSetName` e.g. enforce prefixes
        + `cloudformation:ResourceTypes` to control which resources can be involved in a stack
        + `cloudformation:TemplateUrl` e.g. can only create stacks from this URL (as oppoed to operating on an existing stack resource)

* CloudWatch
    * [**Logs**](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)
        + CloudWatch Agent can be installed on a host (e.g. via SSM) to push logs to CloudWatch Logs. [Troubleshooting info](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/troubleshooting-CloudWatch-Agent.html).
        + Log group: a collection of log streams that share the same retention, monitoring, and access control settings
        + Log stream: a sequence of log events that share the same source
        + Logs last forever unless you set a retention period on a group
        + Subscription filters: define a filter pattern that matches events in a particular log group, send them to Kinesis Data Firehose stream, Kinesis stream, or a Lambda function.
        + Can export log groups (in a particular time range) to S3. Not real time.
        + Can receive events from other account by creating a 'destination' in CloudWatch, which references a receiving Kinesis stream? The destination has a resource-based policy that controls which accounts can write to the destination. CloudWatch Logs on the sender side can then stream to the other account.
    * [Logs Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html?shortFooter=true)
        + Limited query language for analysis and visualization of data in CloudWatch Logs
        + Much more powerful than the native CloudWatch Logs interface
    * [Events](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html)
        + Rules that trigger from either event patterns or a schedule
        + Rules send JSON to one or more targets
    + Has other capabilities (metrics, alarms, scaling) 

* [**CloudTrail**](https://aws.amazon.com/cloudtrail/)
    + Also logs Cognito events, step function logs, and CodeDeploy
    + Logs to S3 and/or CloudWatch Logs
    + Without creating a trail, the event history shows 90 days but excludes various events including all read events
    + A [small number](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html) of services don't log to CloudTrail, notably SimpleDB
    + Trails by default don't include data events (incl S3 object activity and Lambda execution). Can specify those resources you want to record.
    + Trails are regional, but you can create a global trail which creates identitical trails in all regions. Limit of 5 trails per region.
    + eventSource: what service produced the event.
    + Can enable SNS notifications for when a new log _file_ is produced
    + Can set up CloudWatch metric filters for certain events to trigger a CloudWatch Alarm

* [**Config**](https://aws.amazon.com/config/)
    + Resource inventory, configuration history, and configuration change notifications
    + Configuration changes or deviations -> SNS, CloudWatch Events, console dashboard, S3
    + Regional, but can aggregate data across (a limited set of supported) regions and accounts. Can't centrally manage rules.
    + Inspects software running on SSM managed EC2 instances, incl OS version, installed apps, network config.
    + Configuration changes sent to 'delivery channel' - S3 bucket & SNS topic
    + Console provides a timeline view of configuration changes
    + AWSConfigRole is the managed audit role; also needs permisisons for the SNS topic & S3 bucket.
    * Rules
        + Continuously evaluate configs against rules
        + Retrospective and non-enforcing
        + Custom rules in Lambda
        + Soft limit of 50 active rules
        + Periodic (hourly to daily) or change-triggered. Change-triggered must be constrained by tag/resource type/resource id


* [Control Tower](https://aws.amazon.com/controltower/)
    + In preview at the time of writing - likely to become an important security service as it enables easier robust multi-account setups.

* Management Console
    + The web console!

* [Service Catalog](https://aws.amazon.com/servicecatalog/)
    + Portfolio: collection of catalogs. Catalogs: collection of products. Product: CloudFormation template (with the usual optional CloudFormation parameters).
    + Portfolios can be shared across accounts.
    + Admin access control is via IAM. User access control is initially via IAM -  You need ServiceCatalogEndUserAccess to use Service Catalog. It doesn't support resource-level permissions nor resource-based policies, which is weird. Portfolio access is instead managed within Service Catalog by associating IAM users/groups/roles with a Portfolio.
    + Launch role: a role that is used to run the templates, instead of the user having the necessary permissions. Don't think the user needs iam:PassRole to use it - so a way of constraining user of the permissions in the role.

* [**Systems Manager (SSM)**](https://aws.amazon.com/systems-manager/)
    + Group resources of different types together based on a query, e.g. an application. 
    + Many features require the Agent installed - many AWS AMIs include it by default. EC2 instances need an instance profile for a role that has the necessary permissions to allow the agent to interact with SSM.
    * Insights dashboard - per resource group
        + Shows CloudTrail, Config, software inventory, and patch compliance 
        + Can integrate CloudWatch dashboards, Trusted Advisor notificaitons, Personal Health Dashboard
        + Potentially useful for understanding baseline usage patterns to contrast with during an incident
    + Inventory - applications, files, network configurations, Windows services, registries, more 
    * Automation
        + documents of tasks to run; scheduled, triggered, or manually launched
        + Approval feature - configure approvals required (via the console) before it continues
        + Documents can have roles, and users can have permission to run documents - nice restriction of privileges to particular tasks
    * Run command
        + Sometimes called EC2 run command
        + Logs via CloudTrail
        + Can be triggered by CloudWatch Events
    * Session Manager - browser based shell w/ IAM & CloudTrail
        + Can log session data to S3 and/or CloudWatch Logs
    * Patch Manager
    * State Manager - specify OS configuration, rollout schedule, compliance reporting
    * Parameter store
        + Can be tagged + organized in a hierarchy.
        + KMS for encryption - users need KMS permissions to use the corresponding CMK (can restrict using a condition on kms:EncryptionContext to just particular parameters)
        + IAM resource per-parameter
        + 10k params per account
    + Patch Manager and State Manager can operate on on-prem instances too
    + Lots of resources, no resource-based policies
    + The CloudWatch Agent can send SSM actions on the host to CloudWatch Logs

* [**Trusted Advisor**](https://aws.amazon.com/premiumsupport/technology/trusted-advisor/faqs/)
    + 7 free checks, all checks with appropriate support plan.
    + API; Console; Weekly notification email with summary of findings
    + Can exclude resources from all checks. Can't suppress individual checks.
    + Cost optimization, security, service limits, fault tolerance, performance
    + Security checks: 
        + Security group open access to specific high-risk ports
        + Security group unrestricted access
        + Open write and List access to S3 buckets
        + MFA on root account
        + Overly permissive RDS security group
        + Use of cloudtrail
        + Route 53 MX records have SPF records
        + ELB with poor or missing HTTPS config
        + ELB security groups missing or overly permissive
        + CloudFront cert checks - expired, weak, misconfigured
        + IAM access keys not rotated in last 90 days
        + Exposed access keys on GitHub etc 
        + Public EBS or RDS snapshots
        + Missing or weak IAM password policy

* Snow Family (see storage)

## Mobile

* API Gateway (see network & content delivery)

## Networking & Content Delivery

* [API Gateway](https://aws.amazon.com/api-gateway/)
    + Logs to CloudWatch
    + sigV4 signed requests with IAM; or Cognito User Pool token verification; or Lambda authorizers for other token verification
    + Can configure with a 'client-side' certificate that API gateway uses for authenticating its requests to backend servers
    + Resource based policies attached to API, the only action is `execute-api:Invoke`. Can use to allow cross-account access, or in combo with conditions to constrain access to specific VPCs / VPC endpoints / IP ranges etc. Rather complex [logic](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-authorization-flow.html) for evaluating them in combo with identity policies.
    + Supports rate limiting requests from an IP
    + Private APIs - only accessible through VPC endpoints.
    + Private integrations - connect to non-public VPC resources behind the API. Create an ELB network load balancer in the VPC, API Gateway associates it with a 'vpclink' VPC endpoint 
    + CORS - necessary to allow cross-origin requests; will need to be configured if using the default API gateway URLs rather than proxying via CloudFront, otherwise browsers won't honor requests to the API.
    + Integrates with WAF

* [CloudFront](https://aws.amazon.com/cloudfront/)
    + Optional access logs to S3 - bucket ACL configured to give the awslogsdelivery account full control. Metrics via CloudWatch.
    + Field level encryption - CloudFront can encrypt specific POST fields with a public key you've configured. Reduces exposure of sensitive data as it passes through the backend.
    + HTTPS: can configure HTTP, redirect to HTTPS, or HTTPS only for client side. For origin side can do HTTP, match viewer, or HTTPS.
    + To serve content from S3 _only_ via CloudFront, create an 'origin access identity' for the distribution, then create a bucket policy that blocks public access and allows the special `"Principal":{"CanonicalUser":"<CloudFront Origin Identity Canonical User ID>"}`
    + Can only allow specific geographic regions based on IP
    + Can require signed URLs or signed Cookies - CloudFront creates keypairs for each "trusted signer" AWS account, and the account generates time-limited signed URLs or Cookies for clients to use.

* [Route 53](https://aws.amazon.com/route53/)
    + Private DNS - create a hosted zone associated with at least one VPC. 

* VPC PrivateLink - see VPC Interface Endpoints

* App Mesh
    + Envoy for ECS/EKS. Security is important if your app uses this, but unlikely to be in scope of the cert.

* [Direct Connect](https://aws.amazon.com/directconnect/)
    + Dedicate WAN link to AWS
    + Alternative backend to Virtual Private Gateway instead of "vanilla internet"
    + Doesn't use encryption?
    + Virtual interfaces are either private - access to a VPC, or public - access to AWS public endpoints. Can have multiple interfaces per connection if its fast enough.

* [Transit Gateway](https://aws.amazon.com/transit-gateway/)
    + "A hub that controls how traffic is routed among all the connected networks which act like spokes"
    + Instead of lots of (1:1) VPC peering relationships and lots of (1:1) VPN connections, connect each VPC to the single transit gateway and manage centrally

* [**VPC**](https://aws.amazon.com/vpc/)
    + Spans all AZs in a single region
    + Soft limit of 5 VPCs per region
    + Has a CIDR, can have 4 additional CIDRs
    + See [example scenarios](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Scenarios.html)
    + [Policy resources and condition keys](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/ec2-api-permissions.html)
        + Most resources support the `ec2:Vpc` and `ec2:Region` condition keys. Other notable ones listed below.
        + `arn:aws:ec2:<region>:<account>:internet-gateway/igw-id`
        + `arn:aws:ec2:<region>:<account>:network-acl/nacl-id`
        + `arn:aws:ec2:<region>:<account>:network-interface/eni-id` and `ec2:{Subnet,AvailabilityZone}`
        + `arn:aws:ec2:<region>:<account>:route-table/route-table-id`
        + `arn:aws:ec2:<region>:<account>:security-group/security-group-id`
        + `arn:aws:ec2:<region>:<account>:vpc/vpc-id` and `ec2:Tenancy`
    * Network interfaces
        + Has one or more IP addresses, a MAC address, one or more security groups, 
        + Can be moved between EC2 instances
        + Can't move the primary interface of an instance
    * Egress options:
        * Internet Gateway
            + Attached to VPC
            + Interface must have a public address, but the gateway does NAT so incoming traffic is addressed to the interface's private address
        * Virtual Private Gateway
            + IPSec VPN attached to a VPC
            + Need a corresponding customer gateway in the other network(s)
            + Route table(s) need updating to point at customer gateway. Route propagation can do this automatically.
            + Security groups need rules to allow access from remote network
        * VPC Peering Connection
            + VPC peering can cross both accounts and regions, but is not transitive between VPCs
        * VPC Endpoints
            + To keep service traffic within AWS. No public IP needed.
            + Endpoint policies - resource policies that constrain what service actions are possible via that endpoint.
            + S3 bucket policies can limit access to a specific endpoint or VPC using aws:sourceVpce and aws:sourceVpc, e.g.:
                ```json
                {   "Sid": "specific-vpc-endpoint",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:sourceVpce": "vpce-1a2b3c4d"
                        }
                    },
                ```
            + Similarly can use `aws:sourceVpce` in an identity policy for DynamoDB
            * Gateway Endpoint
                + Gateway in the VPC that you route to with a special-case entry in route tables
                + S3 and DynamoDB only - they don't have interface endpoints
            * Interface Endpoint (PrivateLink)
                + Elastic network interface with a private IP address
                + In a subnet and security group(s) - security group needs to allow outbound access to the service
                + Several services including EC2, ELB, SNS, CloudWatch, Systems Manager, and various Marketplace products.
                + Has an endpoint specific DNS hostname. 
                + Private DNS allows you to use the normal hostname for the services, by creating a DNS zone in the VPC using Route53 that has a record for the service that resolves to the interface's private IP address.
        * NAT Gateway
            + To prevent unsolicited inbound connections but allow outbound connections for instances without a public IP
            + Within a public subnet, in a specific AZ
            + The subnet's NACL applies, but NAT Gateways aren't in any security groups
            + Has an Elastic IP address
            + Connects to an Internet Gateway
            + Can be used by instances in a different (private) subnet in the same VPC
        + Also see Transit Gateway
    * Subnets
        + Within a single AZ
        + Can be shared across accounts!
        + CIDR is within the VPC's CIDR and can't overlap other subnets in the VPC. Must have IPv4 CIDR.
        + Associated with a route table for outbound traffic. Default to VPC's main route table. 
        + Public subnet = route table includes an internet gateway. Otherwise called a private subnet.
        + Instances have a private IP and optionally (configured at subnet + instance level) either a public IP (random from AWS' pool) or an Elastic IP (persistent, owned by your account)
        + Instances with a public/elastic IP also get a public DNS hostname
        * Network ACLs
            + Each subnet has a NACL
            + What traffic can enter/exit a subnet
            + Stateless - must have explicit inbound and outbound rules - replies aren't special. For web-facing servers, need to allow outbound ephemeral ports e.g. 1024+ for all addresses
            + VPC default NACL is used for new subnets, its initial rules allow all traffic
            + Rules: Allow/Deny, dest port, src/dst addr, protocol.
            + Rules evaluated in order until one matches. Default deny (there's an immutable final deny rule that matches all).
            + Custom NACLs start with no rules (except the deny-all).
    * Route tables
        + Exist in the VPC. Subnets are associated with a single route table
        + The most specific route that matches is used
        + Always have unmodifiable local routes for in-VPC traffic
        + Need to have entries for gateways and VPC peering
        + New VPCs have a main route table. You can make a custom route table the main one.
    * Flow logs
        + to S3 or CloudWatch Logs
        + Log streams/files are per interface, but can be configured at VPC, subnet, or network interface level
        + Capture window: ~10 minutes after which a log entry is published
        + `<version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>`
        + Doesn't record: Amazon DNS requests (does record requests to a custom DNS server); 169.254.169.254 metadata; DHCP; traffic to the default VPC router
        + Identity policies only - no resource based policies
        + Flow logs service needs a role to assume so it can publish logs to S3 or CloudWatch, and users need iam:PassRole for the role
        + S3 Bucket policy must allow the service to PutObject + a bit more. Automatically created if the flow log creator can create and modify bucket policies.
    * Security groups
        + What traffic can flow to/from an instance
        + Allow rules only, direction specific.
        + Multiple SGs per instance are possible.
        + Rules on src/dest, dest port, protocol (TCP, UDP, etc)
        + src/dest can be ip range; a sg in this VPC or a peered one; service prefix list for gateway endpoints
        + Default rules in a new group: no inbound, all outbound.
        + The default security group also allows inbound from other instances in the sg.
        + Stateful - responses are always allowed
        + Can reference SGs in peered VPCs.

## Storage

* [**S3**](https://aws.amazon.com/s3/)
    * Monitoring
        + CloudTrail by default records bucket-level actions
        + Can enble CloudTrail logging of object-level actions by setting that property on a bucket in S3 (can choose read/write)
        + Server access logging - separate audit log, configured per-bucket, that stores events in a bucket. Destination bucket needs a special ACL (see ACL section). Best-effort delivery.
    + Buckets and Objects are the main resources, each have various subresources (versioning, policies/acls, ...)
    + Buckets are truly global - no region or account ID in their ARN
    + The account that uploads objects owns them - even if the bucket is owned by a different account! Bucket owner pays for storage, manages storage class, and can delete or deny access to any object.
    + [Access control](https://docs.aws.amazon.com/AmazonS3/latest/dev/how-s3-evaluates-access-control.html) logic is complex. That page doesn't include "block public access" logic.
        + User needs to have permission - using identity policies (or user is the root of an account)
        + For bucket operations: bucket needs to have permission - either just bucket policy/acl for user in a different account, or both bucket policy/acl and identity policy if user is in the same account
        + For object operations: User has to have permission (or be root). Bucket policy/acl has to _not deny_. Object ACL (or bucket policy) has to allow. Three different account contexts in play - the user's account (IAM), the bucket's account (for bucket ACL/policy & identity policy if same-account), the object's account (for object ACL).
    * Bucket policies
        + Bucket resource-based policy.
    * ACLs
        + Bucket and object resource-based policy
        + Default ACL grants the owner account full control
        + List of grants, each grant gives a grantee (an AWS account or predefined group) a permission
        + Grantee groups: Authenticated Users group - _any_ AWS user. All Users group - incl anonymous. Log Delivery group - S3 audit logs.
        + Permissions: READ, WRITE (only applies to buckets - allows overwriting and deleting objects), READ/WRITE ACL, FULL CONTROL (all of the above)
        + Don't use bucket ACLs except for allowing write access to the Log Delivery Group for access logging. This is the only way.
    * Block Public Access
        + Applied to specific buckets, or all buckets in an account
        + BlockPublicAcls - can't create new public bucket or object ACLs
        + IgnorePublicAcls - existing (and new) public ACLs are ignored
        + BlockPublicPolicy - can't create public bucket polciies (only really works if applied account-wide, otherwise you can undo it via a bucket policy that allows modifying this policy...)
        + RestrictPublicBuckets - blocks all anonymous and cross-account access to a bucket
    + Query string authentication - instead of using the authorization header, you specify the access key ID and signature in 
    * Event notifications
        + Per bucket.
        + Sources: object creation, deletion, restoration from Glacier, and loss (for reduced redunadancy class)
        + Destinations: SNS topic, SQS queue, Lambda
    + Versioning
        + Enable on a bucket, then all object versions (including deleted one) remain available. Bucket owner can permanently delete.
        + Object lock: can't be deleted or overwritten until a particular date. Governance mode - needs s3:BypassGovernanceMode to override; Compliance mode - can't be overridden, even by root. Legal Hold - no end date (separate perm needed to override). Applies to an individual object version.
        + MFA delete: have to provide a TOTP code to delete (separate to IAM MFA) in `x-amz-mfa` header
    * Lifecycle policies 
        + Transition action - change storage class
        + Expiration action - delete
        + e.g. archive old versions to glacier, then delete.
    * Encryption
        + SSE-S3  - pure S3 managed encryption
        + SSE-KMS - standard KMS integration like other services
        + SSE-C   - you send the plaintext encryption key in the request (!)
        + The SDKs also ease support for client-side encryption

* [Elastic Block Store (EBS)](https://aws.amazon.com/ebs/)
    + Redundancy but only within a single AZ
    + Snapshots might be useful for recovery
    + Encryption (if enabled) happens on the EC2 server side (outside the EC2 VM), hence encrypted in transit and rest. Uses KMS - wrapped data key stored alongside volume.
    + `ec2:CreateVolume` action paired with `ec2:Encrypted` condition key can enforce use of encrypted volumes

* [EFS](https://aws.amazon.com/efs/)
    + NFS filesystem
    + Standard posix permissions
    + Mount targets appear as endpoints in a VPC, so Security Groups can control access
    + IAM only used for administration
    + transparent encryption at rest with KMS (could monitor compliance with a CloudWatch alarm over CloudTrail logs)
    + NFS over TLS is an option with the EFS mount helper (stunnel)

* [S3 Glacier](https://aws.amazon.com/glacier/)
    + Encrypted by default
    + Value access policies - resource based policy attached to a vault. Like a bucket policy.
    + Vault lock policies - a vault access policy that can be locked to prevent changes to it
    + Other than the global ones and tags, supports `glacier:ArchiveAgeInDays` condition key - nice in combo with the `glacier:DeleteArchive` action
    + Retrieval requires job initiation then getting the output from the job
    + Data retrieval policy: a resource-based policy for regions? They don't describe it as such, but each region can have one policy that constrains Glacier retrievals to free tier / maximum transfer rate / unlimited.

* [Backup](https://aws.amazon.com/backup/)
    + Centralise backups across RDS, DynamoDB, EBS, EFS, Storage Gateway. Uses those services' native capabilities (snapshots etc)
    + Can be encrypted in transit and at rest. Uses the service's native encryption capabilities, or for EFS where the backup functionality comes from Backup itself, it does the usual KMS encryption. Other than EFS, encryption depends on whether the source is encrypted (note DynamoDB tables are always encrypted at rest).
    + Resources: plans, vaults, recovery points. 
    + Resource-based policy for vaults, but these only constrain _vault_ access, not access to the underlying backup like an EBS or RDS snapshot.

* [Snow family](https://aws.amazon.com/snow/)
    + All use encryption integrated with KMS. Encryption is performed client-side prior to transfer to the device.
    + Snowball and Snowball edge use tamper-resistant designs and active monitoring using a TPM
    + API calls use IAM as normal. The Snowball devices don't - combo of an encrypted manifest & access code give full control of it.
    + Snowmobile is a little different :D ... "dedicated security personnel, GPS tracking, alarm monitoring, 24/7 video surveillance, and an optional escort security vehicle"

* [Storage Gateway](https://aws.amazon.com/storagegateway/)
    + SMB/NFS front end to S3 - file gateway
    + iSCSI front end to Glacier/S3 - tape gateway / volume gateway
    + Encrypted in transit and at rest. By default uses SSE-S3, can configure to use SSE-KMS.
    + iSCSI has its own authentication model (CHAP)
