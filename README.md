# AWS SRA Verify MCP Server

Assess your AWS environment against security best practices using the [AWS Security Reference Architecture (SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html). This MCP server provides automated checks for GuardDuty, CloudTrail, IAM, SecurityHub, and other critical AWS security services across your organization's accounts.

## What It Does

[SRA Verify](https://github.com/awslabs/sra-verify) validates that native AWS security services are properly configured at scale across your AWS Organization. It checks multiple account types — management, audit, log-archive, and application — and returns detailed pass/fail findings for each security control.

> Security and Compliance is a shared responsibility between AWS and the customer. SRA Verify and the SRA Verify MCP server may help a customer implement controls and best practices on the customer side of the shared responsibility model. Visit the [Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/) to learn more.

### MCP Tools

| Tool                          | Description                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| `list_services`               | List all AWS services supported by SRA Verify                                          |
| `list_checks_by_service`      | Get checks for a specific service (e.g., GuardDuty, CloudTrail, IAM)                   |
| `list_checks_by_account_type` | Get checks filtered by account type (management, audit, log-archive, application, all) |
| `describe_check`              | Get detailed info about a specific check including severity and requirements           |
| `run_check`                   | Execute a security check and return findings with pass/fail status                     |

### Supported Services

SRA Verify covers a wide range of AWS security services including: Access Analyzer, Audit Manager, CloudTrail, CloudWatch, Config, GuardDuty, IAM, Inspector, Macie, Organizations, S3, Security Hub, Security Lake, Shield, WAF, and more. Review the full [list of checks](https://github.com/awslabs/sra-verify/blob/main/docs/checks.txt) on the SRA Verify Github.

> Note: SRA Verify contains checks for several services, but may not contain a check for every consideration of the AWS Security Reference Architecture. Review the [AWS Prescriptive Guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) for more information on AWS Security Reference Architecture.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager
- AWS credentials with appropriate read permissions for security services
- Access to an AWS Organization with SRA account structure (management, audit, log-archive accounts)

### Cross-Account Role Setup

To scan member accounts in your AWS Organization, SRA Verify needs an IAM role deployed to each account it will assess. The included `1-sraverify-mcp-roles.yaml` CloudFormation template creates this role with least-privilege permissions.

> Note: You should use least privilege to restrict the AI agent permissions. The example provided is least-privilege read-only commands, but you should review and update to meet your organizations policies.

### Deploy via CloudFormation

Use [CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html) to deploy the role across your organization:

1. Navigate to **CloudFormation > StackSets** in your management account
2. Choose **Create StackSet** and upload `1-sraverify-mcp-roles.yaml`
3. Set the `Role` parameter to the ARN of the IAM role or user that will run SRA Verify (the principal your AWS profile authenticates as)
4. Deploy to your target accounts (or the entire organization)

The template creates:
- **SRAMemberMCPRole** — an IAM role that SRA Verify assumes in each account
- **SRAVerifyMCPLeastPrivilege** — a managed policy with read-only permissions scoped to the AWS services SRA Verify checks
- **SRAVerifyMCPCheckPermissions** — additional permissions for account-level checks

The role's trust policy allows only the principal you specify in the `Role` parameter to assume it.

> Note: StackSets don't apply to the management account. You must also deploy  `1-sraverify-mcp-roles.yaml` as a standalone CloudFormation template to your management account.

## Setup

### Kiro CLI (Agent Mode)

#### Create a Custom Agent (Optional)

You can create a dedicated SRA Verify agent for quick access:

Open Kiro or VS Code to create a new agent configuration file.
```bash
kiro ~/.kiro/agents/sra.json
```

Enter the following example configuration file
```json
{
  "name": "sra",
  "description": "AWS Security Reference Architecture compliance checker",
  "prompt": "You are an AWS security expert specializing in SRA compliance validation. Use the SRA Verify MCP tools to help users assess their AWS environment against security best practices. When users ask about security checks, proactively discover available checks, explain what they validate, and run them with the appropriate account IDs and parameters. Always provide clear summaries of findings with actionable recommendations.",
  "mcpServers": {
    "awslabs.sraverify-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/sra-verify-mcp/awslabs/sraverify_mcp_server/",
        "run",
        "server.py"
      ],
      "disabled": false,
      "env": {
        "AWS_PROFILE": "my-profile" //Optional, you can remove this to use your default AWS credential chain
      }
    }
  },
  "tools": [
    "*"
  ],
  "toolAliases": {},
  "allowedTools": [
    "@awslabs.sraverify-mcp-server/list*",
    "@awslabs.sraverify-mcp-server/describe*"
  ],
  "resources": [],
  "hooks": {},
  "toolsSettings": {},
  "useLegacyMcpJson": true,
  "model": null
}
```

Update "/path/to/sra-verify-mcp/awslabs/sraverify_mcp_server/" with the absolute path to your cloned repository. You can update `my-profile` with the AWS CLI profile that has permissions to assume the `SRAMemberMCPRole`, or remove it to use your default AWS credentials.

To invoke the agent, include `--agent sra` when starting a new chat.

```bash
kiro-cli chat --agent sra
```

## Usage Examples

### Kiro CLI Agent Prompts

> Note: These prompts are provided as an example. Generative AI is non deterministic and you may get different results. Always use least privilege and human-in-the-loop to prevent unwanted changes.

Once configured, you can use natural language prompts with the Kiro CLI agent:

**Discovery:**
```bash
[sra] > List all AWS services that SRA Verify can check
Running tool list_checks_by_account_type with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "account_type": "all"
 ⋮  }
 - Completed in 0.16s

> Based on the available checks, SRA Verify can assess security compliance for the following 27 AWS services:

1. IAM Access Analyzer - External access analysis and organization-wide zone of trust monitoring
2. Account - Alternate contact configuration (security, billing, operations)
3. AuditManager - Continuous audit and compliance assessment
4. CloudTrail - Organization trail configuration, logging, and encryption
5. Config - Configuration recording, aggregation, and compliance tracking
6. EC2 - EBS encryption by default
7. FirewallManager - Centralized firewall policy management across security groups, WAF, Shield, Network Firewall, and
DNS Firewall
8. GuardDuty - Threat detection across multiple data sources (DNS, VPC Flow, S3, EKS, RDS, Lambda, EC2)
9. Inspector - Vulnerability scanning for EC2, ECR, and Lambda
10. Macie - Sensitive data discovery and classification in S3
11. S3 - Public access block settings
12. SecurityHub - Central security posture management and standards compliance
13. SecurityIncidentResponse - Incident response service configuration and coverage
14. SecurityLake - Centralized security data lake with multiple log sources
15. Shield - DDoS protection configuration and resource coverage
16. WAF - Web application firewall associations across CloudFront, ALB, API Gateway, AppSync, Cognito, App Runner,
Verified Access, and Amplify
```

```bash
[sra] > Show me all GuardDuty checks available
Running tool list_checks_by_service with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "service": "GuardDuty"
 ⋮  }
 - Completed in 0.14s

> Here are all 25 GuardDuty checks available in SRA Verify:

## Application Account Checks (12)
Core Configuration:
- **SRA-GUARDDUTY-01** (HIGH) - GuardDuty detector exists
- **SRA-GUARDDUTY-02** (LOW) - GuardDuty finding frequency is set
- **SRA-GUARDDUTY-03** (HIGH) - GuardDuty detector is enabled

Data Sources:
- **SRA-GUARDDUTY-04** (MEDIUM) - DNS logs enabled
- **SRA-GUARDDUTY-05** (MEDIUM) - VPC flow logs enabled
- **SRA-GUARDDUTY-08** (HIGH) - CloudTrail logs enabled

Protection Features:
- **SRA-GUARDDUTY-06** (HIGH) - S3 protection enabled
- **SRA-GUARDDUTY-07** (HIGH) - EKS protection enabled
- **SRA-GUARDDUTY-09** (HIGH) - Malware protection for EBS enabled
- **SRA-GUARDDUTY-10** (HIGH) - RDS protection enabled
- **SRA-GUARDDUTY-11** (HIGH) - EKS runtime protection enabled
- **SRA-GUARDDUTY-12** (HIGH) - Lambda protection enabled

Agent Management:
- **SRA-GUARDDUTY-17** (HIGH) - EKS addon management enabled
- **SRA-GUARDDUTY-18** (HIGH) - ECS Fargate agent management enabled
- **SRA-GUARDDUTY-19** (HIGH) - EC2 agent management enabled

## Management Account Checks (2)
- **SRA-GUARDDUTY-13** (HIGH) - Service administration delegated
- **SRA-GUARDDUTY-14** (HIGH) - Delegated admin is audit account

## Audit Account Checks (7)
Organization-Wide Configuration:
- **SRA-GUARDDUTY-15** (HIGH) - Auto-enablement configured
- **SRA-GUARDDUTY-16** (HIGH) - Member account limit not reached

Auto-Enablement for Features:
- **SRA-GUARDDUTY-20** (HIGH) - S3 data events auto-enablement configured
- **SRA-GUARDDUTY-21** (HIGH) - EBS Malware Protection auto-enablement configured
- **SRA-GUARDDUTY-22** (HIGH) - EKS Audit Logs auto-enablement configured
- **SRA-GUARDDUTY-23** (HIGH) - Runtime Monitoring auto-enablement configured
- **SRA-GUARDDUTY-24** (HIGH) - Lambda Network Logs auto-enablement configured
- **SRA-GUARDDUTY-25** (HIGH) - RDS Login Events auto-enablement configured
```

**Running Checks:**
```bash
[sra] > Run SRA-GUARDDUTY-01 check for audit account 123456789012 using role SRAMemberMCPRole

Running tool run_check with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "check_id": "SRA-GUARDDUTY-01",
 ⋮    "audit_accounts": [
 ⋮      "123456789012"
 ⋮    ],
 ⋮    "log_archive_accounts": null,
 ⋮    "role_arn": "arn:aws:iam::123456789012:role/SRAMemberMCPRole"
 ⋮  }

Allow this action? Use 't' to trust (always allow) this tool for the session. [y/n/t]:

[sra] > y

 - Completed in 11.689s

> ## SRA-GUARDDUTY-01 Check Results

Account: 123456789012 (Code Prod)
Status: Completed with 1 failure

### Summary
- ✅ Passed: 16 regions
- ❌ Failed: 1 region
- **Total:** 17 regions checked

### Failed Region
ap-northeast-3 (HIGH severity)
- **Issue:** GuardDuty detector does not exist
- **Remediation:** Enable GuardDuty in ap-northeast-3

### Passing Regions
GuardDuty detectors are properly configured in:
- ap-south-1, eu-north-1, eu-west-3, eu-west-2, eu-west-1
- ap-northeast-2, ap-northeast-1, ca-central-1, sa-east-1
- ap-southeast-1, ap-southeast-2, eu-central-1
- us-east-1, us-east-2, us-west-1, us-west-2

### Recommendation
Enable GuardDuty in ap-northeast-3 to ensure comprehensive threat detection coverage across all AWS regions, even those not actively used for workloads. This prevents blind spots where unauthorized activity could go undetected.

 ▸ Time: 28s
```

**Comprehensive Validation:**
```bash
[sra] > Run all GuardDuty checks for my audit account 123456789012 in us-east-1 and summarize the results

Running tool run_check with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "audit_accounts": [
 ⋮      "123456789012"
 ⋮    ],
 ⋮    "check_id": "SRA-GUARDDUTY-01",
 ⋮    "region": "us-east-1"
 ⋮  }

Allow this action? Use 't' to trust (always allow) this tool for the session. [y/n/t]:

[sra] > y

Running tool run_check with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "audit_accounts": [
 ⋮      "123456789012"
 ⋮    ],
 ⋮    "check_id": "SRA-GUARDDUTY-02",
 ⋮    "region": "us-east-1"
 ⋮  }

Allow this action? Use 't' to trust (always allow) this tool for the session. [y/n/t]:

[sra] > y

Running tool run_check with the param (from mcp server: awslabs.sraverify-mcp-server)
 ⋮  {
 ⋮    "audit_accounts": [
 ⋮      "123456789012"
 ⋮    ],
 ⋮    "check_id": "SRA-GUARDDUTY-03",
 ⋮    "region": "us-east-1"
 ⋮  }

Allow this action? Use 't' to trust (always allow) this tool for the session. [y/n/t]:

[sra] > y

 - Completed in 1.150s

 - Completed in 1.65s

 - Completed in 1.592s

_truncated the other 22 run_check calls_

> ## GuardDuty Security Assessment Summary

Account: 123456789012 (Audit)
Region: us-east-1
Total Checks: 25

### Overall Results
- ✅ Passed: 23 checks (92%)
- ❌ Failed: 1 check (4%)
- ⚠️ Errors: 1 check (4%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Critical Issues

❌ FAILED - SRA-GUARDDUTY-13: GuardDuty service administration NOT delegated (HIGH)
- **Issue:** GuardDuty service administration is not delegated to any account
- **Impact:** Lack of centralized management reduces security visibility and control across the organization
- **Remediation:** Delegate GuardDuty administration to the audit account (123456789012) from the management account using AWS Organizations

⚠️ ERROR - SRA-GUARDDUTY-14: Cannot verify delegated admin configuration (HIGH)
- **Issue:** BadRequestException when accessing GuardDuty organization information
- **Impact:** Cannot verify if the delegated admin is properly configured as the audit account
- **Remediation:** Check IAM permissions and AWS Organizations configuration

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Passing Checks Summary

✅ Core Configuration (3/3)
- Detector exists
- Detector is enabled
- Finding frequency set (SIX_HOURS)

✅ Data Sources (3/3)
- DNS logs enabled
- VPC flow logs enabled
- CloudTrail logs enabled

✅ Protection Features (6/6)
- S3 protection enabled
- EKS protection enabled
- Malware protection for EBS enabled
- RDS protection enabled
- EKS runtime protection enabled
- Lambda protection enabled

✅ Agent Management (3/3)
- EKS addon management enabled
- ECS Fargate agent management enabled
- EC2 agent management enabled

✅ Organization Configuration (7/7)
- Auto-enablement configured for new accounts
- Member account limit not reached
- S3 data events auto-enablement configured
- EBS Malware Protection auto-enablement configured
- EKS Audit Logs auto-enablement configured
- Runtime Monitoring auto-enablement configured
- Lambda Network Logs auto-enablement configured
- RDS Login Events auto-enablement configured

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Key Recommendations

1. Critical: Delegate GuardDuty administration to this audit account from the management account to enable centralized security management across the
organization

2. Investigate: Resolve the permissions error for organization-level checks (SRA-GUARDDUTY-14)

3. Optional: Consider changing finding frequency from 6 hours to 15 minutes or 1 hour for faster threat response in critical environments

Your GuardDuty configuration is excellent with comprehensive protection features, all data sources enabled, and proper auto-enablement policies for new
accounts. The primary gap is the missing delegated administration setup.

 ▸ Time: 1m 47s
```


### Kiro IDE (Power)

> Note: These prompts are provided as an example. Generative AI is non deterministic and you may get different results. Always use least privilege and human-in-the-loop to prevent unwanted changes.

The SRA Verify Power bundles the MCP server with onboarding workflows and steering files for a guided experience.

#### Install the Power

1. Open Kiro IDE
2. Before installing the power, update the `path/to/sra-verify-mcp/awslabs/sraverify_mcp_server/` in mcp.json with the absolute path to your cloned repository.
3. Open the Powers panel (choose the Powers icon in the sidebar or use the Command Palette: **Kiro: Open Powers**)
4. Choose **Add Custom Power**.
5. Choose **Import power from a folder**.
6. Select /path/to/powers/sra-verify

#### Configure Your AWS Profile

After installing the power, update the AWS profile in the MCP configuration:

1. Open `~/.kiro/settings/mcp.json` in your workspace. You can also choose the edit button next to MCP Servers in the Kiro tab.
2. Find the `AWS_PROFILE` value — it defaults to `SRA_VERIFY_MCP_PROFILE_NAME`
3. Replace `SRA_VERIFY_MCP_PROFILE_NAME` with your actual AWS CLI profile name:

```json
{
  "mcpServers": {
    "power-sra-verify-awslabs.sraverify-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/sra-verify-mcp/awslabs/sraverify_mcp_server/",
        "run",
        "server.py"
      ],
      "disabled": false,
      "env": {
        "AWS_PROFILE": "my-profile" // Update this profile
      }
    }
  }
}
```

#### Run Onboarding

Once the power is installed and configured, use this prompt in Kiro chat to walk through the interactive setup:

```
I just installed SRA Verify power and want to set it up
```

The onboarding workflow will:
- Discover your AWS accounts automatically (or collect them manually)
- Identify your management, audit, and log-archive accounts
- Detect your active AWS regions
- Configure your cross-account role ARN
- Save everything to a steering file for future use

### Kiro IDE Chat Prompts

In Kiro IDE with the power installed you can use natural language prompts. You don't have to be as specific because the steering file gives Kiro additional context.

```markdown
                                    Check my Researcher account for GuardDuty 03

Kiro
> Including Steering Documents sra-verify-environment.md

I'll check the Researcher01 account for GuardDuty check 03. Let me first activate the sra-verify power and then run the check.

> Activated Kiro power sra-verify

Now I'll run the GuardDuty check 03 for the Researcher01 account. Let me first describe the check to understand what it validates, then run it.

> Used Kiro power sra-verify describe_check

> Used Kiro power sra-verify run_check

Great news! The GuardDuty check 03 passed for your Researcher01 account.

Check Results:

Status: PASS ✓
Account: Researcher01 (123456789012)
Region: us-east-1
Severity: HIGH
What was checked: This validates that the GuardDuty detector is enabled in the account. The detector represents the GuardDuty service in the specific region - if disabled, it won't provide threat intelligence.

Finding:

Detector status is ENABLED
Detector ID: 02bf72b27729788EXAMPLE06a31eb
No remediation needed
Your Researcher01 account has GuardDuty properly enabled and running in us-east-1.
```

## Next steps
Think about how you can use this with your other MCP servers and workflows.

- Add ticket system MCP to automatically create tickets for failed findings.
- Use the [AWS MCP Server](https://docs.aws.amazon.com/aws-mcp/latest/userguide/what-is-mcp-server.html) to reference AWS documentation and make AWS API calls
- Ask for remediation guidance, code samples, CloudFromation templates to fix failed findings.