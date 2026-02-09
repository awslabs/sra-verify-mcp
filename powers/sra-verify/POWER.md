---
name: "sra-verify"
displayName: "SRA Verify"
description: "Assess your AWS environment against security best practices for configuring native AWS security services at scale across your organization. Validates AWS Security Reference Architecture (SRA) implementations with automated checks for GuardDuty, CloudTrail, IAM, and other critical security services."
keywords: ["sra", "verify", "scan", "audit", "security", "compliance"]
author: "Jeremy Schiefer (schiefj)"
---

# SRA Verify

**When a user first activates this power or asks I just installed the sra-verify power and want to use it.**

1. **DO NOT search the web** - All documentation is in this file and the onboarding steering file
2. **Start with onboarding** - Read the onboarding steering file to configure the user's AWS environment:
   ```
   Call action "readSteering" with powerName="sra-verify", steeringFile="onboarding.md"
   ```
3. **Follow the onboarding workflow** - Guide the user through gathering their AWS account IDs, regions, and role ARN
4. **Create the configuration file** - Save their settings to `.kiro/steering/sra-verify-environment.md`
5. **Then run checks** - After configuration, help them discover and run security checks

**This power does not require web searches** - everything needed is in the power documentation and MCP tools.

---

## Getting Started

**First time using SRA Verify? Start here:**

Run the interactive onboarding workflow to configure your AWS environment. This will gather your account IDs, regions, and role ARN, then create a personalized configuration file for easy reuse.

**To begin onboarding:**
```
Call action "readSteering" with powerName="sra-verify", steeringFile="onboarding.md"
```

The onboarding workflow will:
- Automatically discover your AWS accounts (or collect them manually)
- Identify your management, audit, and log-archive accounts
- Detect your active AWS regions
- Save everything to a configuration file for future use

**Already configured?** Skip to [Common Workflows](#common-workflows) to start running security checks.

---

## Overview

SRA Verify helps you validate AWS Security Reference Architecture (SRA) implementations across your AWS organization. It provides automated security checks to ensure native AWS security services are properly configured at scale, covering multiple account types (management, audit, log-archive, and application accounts).

The power enables you to run targeted checks by service (GuardDuty, CloudTrail, IAM, etc.) or account type, helping you validate security controls, troubleshoot security gaps, and prepare for audits. Each check validates specific security controls and provides detailed findings with pass/fail status.

Whether you're validating a fresh SRA deployment, monitoring for configuration drift, or preparing for a security audit, SRA Verify gives you the tools to assess and verify your AWS security posture against established best practices.

## Available Steering Files

- **onboarding.md** - Interactive onboarding workflow to configure your AWS environment (account IDs, regions, role ARN) and create a personalized configuration file for easy reuse

## Onboarding

### Quick Start: Interactive Configuration

**New users:** Follow the [Getting Started](#getting-started) section above to run the interactive onboarding workflow.

### Manual Configuration (Advanced)

If you prefer to configure manually or already know your environment details, you'll need the following information when running checks:

### Manual Configuration

If you prefer to configure manually, you'll need the following information when running checks:

**Required Information:**
- **Management Account ID**: Your AWS Organizations management account (12-digit ID)
- **Audit Account ID**: Your centralized security/audit account (12-digit ID)
- **Log Archive Account ID**: Your centralized logging account (12-digit ID)
- **Cross-Account Role ARN**: IAM role that SRA Verify assumes to scan accounts (e.g., `arn:aws:iam::123456789012:role/SRAVerifyRole`)
- **Primary Regions**: AWS regions you want to scan (e.g., `us-east-1`, `us-west-2`)

You'll provide these as parameters when running checks (see workflow examples below).

### Prerequisites

- **AWS Credentials**: Configured AWS credentials with appropriate permissions to read security service configurations
- **AWS Organization**: Access to AWS Organizations with multiple account types (management, audit, log-archive, application)
- **Python & uv**: The MCP server requires Python and the `uv` package manager
- **SRA Knowledge**: Familiarity with AWS Security Reference Architecture concepts and account types

### Installation

The SRA Verify MCP server is already configured in your workspace. No additional installation steps are required.

### Configuration

**Environment Setup:**

Ensure your AWS credentials are configured. The MCP server will use your default AWS credentials or you can specify a profile:

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Or set specific profile
export AWS_PROFILE=your-profile-name
```

**Account Type Identification:**

SRA Verify checks are organized by AWS account type. You'll need to know which accounts serve which roles:
- **Management Account**: AWS Organizations management account
- **Audit Account**: Centralized security tooling and findings
- **Log Archive Account**: Centralized logging destination
- **Application Accounts**: Workload accounts

## Common Workflows

### Workflow 1: Discover Available Checks

Before running checks, explore what's available by service or account type.

**List All Services:**
```
Use list_services tool to see all supported AWS services
```

**List Checks by Service:**
```
Use list_checks_by_service tool with service name (e.g., "GuardDuty", "CloudTrail", "IAM")
```

**List Checks by Account Type:**
```
Use list_checks_by_account_type tool with account type:
- "management" - Management account checks
- "audit" - Audit/Security account checks
- "log-archive" - Log archive account checks
- "application" - Application account checks
- "all" - All checks
```

**Example Discovery Flow:**
1. List all services to see what can be checked
2. Pick a service relevant to your needs (e.g., "GuardDuty")
3. List all checks for that service to see specific validations
4. Review check details before running

### Workflow 2: Run Targeted Security Checks

Execute specific checks to validate security controls.

**Get Check Details:**
```
Use describe_check tool with check_id (e.g., "SRA-GUARDDUTY-01")
Returns: name, service, account_type, description, severity
```

**Run a Single Check:**
```
Use run_check tool with:
- check_id: The specific check to run (e.g., "SRA-GUARDDUTY-01")
- audit_accounts: List of audit account IDs (required for some checks)
- log_archive_accounts: List of log archive account IDs (required for some checks)
- role_arn: Optional IAM role to assume
- region: Optional specific region (defaults to all regions)
```

**Example - Validate GuardDuty Configuration:**
```
1. Describe check: describe_check with check_id="SRA-GUARDDUTY-01"
2. Run check: run_check with check_id="SRA-GUARDDUTY-01",
   audit_accounts=["123456789012"]
3. Review findings and summary in results
```

**Common Errors:**
- **Error: "Missing required parameter: audit_accounts"**
  - Cause: Check requires audit account IDs but none provided
  - Solution: Add audit_accounts parameter with list of account IDs

- **Error: "Access Denied"**
  - Cause: Insufficient AWS permissions
  - Solution: Ensure credentials have read permissions for the service being checked

### Workflow 3: Post-Deployment Validation

After deploying SRA solutions, verify correct configuration across all account types.

**Steps:**
1. **List checks by account type** to see what should be validated
   - Run for "management", "audit", "log-archive", and "application"

2. **Run critical checks first:**
   - GuardDuty enabled and publishing findings
   - CloudTrail logging to log-archive account
   - IAM password policies configured

3. **Review findings:**
   - Check pass/fail status for each finding
   - Review summary for overall compliance
   - Document any failures for remediation

4. **Iterate through remaining checks** based on priority

**Example Check Sequence:**
```
1. GuardDuty checks (audit account)
2. CloudTrail checks (log-archive account)
3. IAM checks (management account)
4. Application account checks (security services enabled)
```

### Workflow 4: Periodic Compliance Monitoring

Run periodic checks to detect configuration drift from SRA standards.

**Monitoring Strategy:**
1. **Identify critical checks** for your organization
2. **Schedule regular validation** (daily, weekly, or triggered by changes)
3. **Track results over time** to identify drift patterns
4. **Alert on failures** for immediate remediation

**Key Checks for Monitoring:**
- Security services remain enabled (GuardDuty, SecurityHub, etc.)
- Logging configurations haven't changed
- WAF rules remain in block mode
- Shield Advanced protections are active
- Cross-account access is properly configured

**Drift Detection:**
- Compare current check results with baseline
- Identify newly failing checks
- Investigate configuration changes in AWS

### Workflow 5: Pre-Audit Preparation

Generate comprehensive evidence of security control implementation before audits.

**Audit Preparation Steps:**
1. **Run all checks** across all account types
   - Use list_checks_by_account_type with "all"
   - Execute each check systematically

2. **Document findings:**
   - Passing checks demonstrate implemented controls
   - Failing checks identify gaps to remediate

3. **Prioritize remediation:**
   - Focus on high-severity findings first
   - Address gaps before auditor review

4. **Generate evidence:**
   - Check results serve as proof of security posture
   - Findings show due diligence in validation

### Workflow 6: Troubleshooting Security Issues

When security alerts aren't appearing or services seem misconfigured, use checks to diagnose.

**Troubleshooting Flow:**
1. **Identify the affected service** (e.g., GuardDuty findings not appearing)
2. **List checks for that service** to see available validations
3. **Run relevant checks** to identify misconfigurations
4. **Review findings** for specific configuration issues
5. **Remediate** based on check results
6. **Re-run checks** to verify fixes

**Common Troubleshooting Scenarios:**
- **No GuardDuty findings in audit account**: Check if GuardDuty is publishing to correct account
- **Missing CloudTrail logs**: Verify CloudTrail is logging to log-archive account
- **Security alerts not triggering**: Check if CloudWatch alarms exist and are configured correctly

## Available MCP Tools

### Discovery Tools

**list_services**
- Lists all AWS services supported by SRA Verify
- No parameters required
- Returns: List of service names

**list_checks_by_service**
- Get all checks for a specific AWS service
- Parameters:
  - `service` (required): Service name (e.g., "GuardDuty", "CloudTrail", "IAM")
- Returns: Dictionary mapping check IDs to check information

**list_checks_by_account_type**
- Get all checks filtered by AWS account type
- Parameters:
  - `account_type` (optional, default="all"): Account type filter
    - "management" - Management account checks
    - "audit" - Audit/Security account checks
    - "log-archive" - Log archive account checks
    - "application" - Application account checks
    - "all" - All checks
- Returns: Dictionary mapping check IDs to check information

**describe_check**
- Get detailed information about a specific check
- Parameters:
  - `check_id` (required): Check ID (e.g., "SRA-GUARDDUTY-01")
- Returns: Check details including name, service, account_type, description, severity

### Execution Tools

**run_check**
- Execute a security check and return results
- Parameters:
  - `check_id` (required): Check ID to run
  - `audit_accounts` (optional): List of audit account IDs (required for some checks)
  - `log_archive_accounts` (optional): List of log archive account IDs (required for some checks)
  - `role_arn` (optional): IAM role ARN to assume for running the check
  - `region` (optional): AWS region to target (if not specified, checks all regions)
- Returns: Dictionary with findings and summary, or error if check fails

## Troubleshooting

### MCP Server Connection Issues

**Problem:** MCP server won't start or connect

**Symptoms:**
- Error: "Connection refused"
- Server not responding
- Tools not available

**Solutions:**
1. Verify Python and uv are installed:
   ```bash
   python --version
   uv --version
   ```

2. Check the server path exists:
   ```bash
   ls -la /path/to/sra-verify-mcp/awslabs/sraverify_mcp_server/
   ```

3. Test server manually:
   ```bash
   cd /path/to/sraverify/sra-verify-mcp/awslabs/sraverify_mcp_server/
   uv run server.py
   ```

4. Review MCP server logs in Kiro
5. Restart Kiro and try again

### AWS Credentials Issues

**Problem:** Checks fail with authentication errors

**Symptoms:**
- Error: "Unable to locate credentials"
- Error: "Access Denied"
- Error: "Invalid security token"

**Solutions:**
1. Verify AWS credentials are configured:
   ```bash
   aws sts get-caller-identity
   ```

2. Check credential expiration (if using temporary credentials)

3. Ensure credentials have necessary read permissions for security services

4. Try specifying a different AWS profile:
   ```bash
   export AWS_PROFILE=your-profile-name
   ```

### Missing Required Parameters

**Problem:** Check fails with missing parameter error

**Symptoms:**
- Error: "Missing required parameter: audit_accounts"
- Error: "Missing required parameter: log_archive_accounts"

**Solutions:**
1. Use describe_check to see what parameters are required
2. Provide audit_accounts parameter for checks that need audit account IDs
3. Provide log_archive_accounts parameter for checks that need log archive account IDs

**Example:**
```
run_check with:
  check_id="SRA-GUARDDUTY-01"
  audit_accounts=["123456789012", "234567890123"]
  log_archive_accounts=["345678901234"]
```

### Check Execution Failures

**Problem:** Check runs but returns errors or unexpected results

**Symptoms:**
- Check completes but shows errors in findings
- Unexpected failure results
- Incomplete results

**Solutions:**
1. Verify you're running the check in the correct account type
2. Check if the AWS service is actually deployed in your environment
3. Ensure the region parameter matches where resources are deployed
4. Review check description to understand what's being validated
5. Verify cross-account permissions if checking centralized services

### Region-Specific Issues

**Problem:** Check doesn't find resources that exist

**Symptoms:**
- Resources exist but check reports them as missing
- Partial results returned

**Solutions:**
1. Verify resources are in the expected region
2. Try specifying the region parameter explicitly:
   ```
   run_check with region="us-east-1"
   ```
3. Some checks run across all regions by default - ensure resources are deployed globally if expected

## Best Practices

- **Start with discovery**: Always list available checks before running them to understand what will be validated
- **Describe before running**: Use describe_check to understand what a check does and what parameters it needs
- **Provide account context**: Supply audit_accounts and log_archive_accounts parameters when running checks to get complete results
- **Run checks in appropriate accounts**: Execute checks from accounts with proper cross-account access permissions
- **Monitor regularly**: Schedule periodic check runs to detect configuration drift early
- **Prioritize by severity**: Focus on high-severity findings first when remediating issues
- **Document baselines**: Record initial check results to track changes over time
- **Use specific regions**: When troubleshooting, specify the region parameter to narrow scope
- **Validate after changes**: Run relevant checks after making infrastructure changes to verify correct configuration
- **Combine with IaC**: Use SRA Verify to validate that Infrastructure as Code deployments match expected security posture

## Configuration

**No additional configuration required** - the MCP server works with your existing AWS credentials and the configuration already set up in your workspace.

**Optional Configuration:**
- Set AWS_PROFILE environment variable to use a specific AWS credential profile
- Configure role_arn parameter when running checks to assume a specific IAM role
- Specify region parameter to target specific AWS regions

## MCP Config Placeholders

**IMPORTANT:** Before using this power, replace the following placeholder in `mcp.json` with your actual value:

- **`PLACEHOLDER_SRA_VERIFY_PATH`**: Path to your SRA Verify MCP server installation directory.
  - **How to get it:**
    1. Clone or locate the SRA Verify MCP server repository on your system
    2. Navigate to the server directory: `awslabs/sraverify_mcp_server/`
    3. Use the full absolute path to this directory
    4. Example: `/Users/yourname/code/sra-verify-mcp/awslabs/sraverify_mcp_server/`

**After replacing the placeholder, your mcp.json should look like:**
```json
{
  "mcpServers": {
    "awslabs.sraverify-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "/Users/yourname/code/sra-verify-mcp/awslabs/sraverify_mcp_server/",
        "run",
        "server.py"
      ],
      "disabled": false
    }
  }
}
```

---

**MCP Server:** awslabs.sraverify-mcp-server
**Installation:** Requires Python, uv, and SRA Verify MCP server repository
