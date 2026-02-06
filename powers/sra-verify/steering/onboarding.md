# SRA Verify Onboarding Guide

This steering file guides you through interactive onboarding to configure SRA Verify for your AWS environment.

---

## Overview

This onboarding workflow will:
1. Gather your AWS environment details (account IDs, regions, role ARN)
2. Create a configuration steering file with your settings
3. Provide ready-to-use commands with your configuration pre-filled
4. Enable quick access to your environment details for future checks

---

## Onboarding Workflow

### Step 1: Gather AWS Environment Information

**Through natural conversation, collect the following information from the user:**

**Offer Automatic Discovery:**

Before asking for account IDs manually, offer to discover them automatically:

"I can help you discover your AWS account information automatically using AWS CLI commands. Would you like me to:
1. Identify your current account and check if it's the management account
2. List all member accounts in your AWS Organization

This requires AWS CLI access with Organizations permissions. Should I try automatic discovery, or would you prefer to provide the account IDs manually?"

**If user agrees to automatic discovery, proceed with Step 1a (Automatic Discovery).**
**If user prefers manual entry, proceed with Step 1b (Manual Entry).**

---

### Step 1a: Automatic Discovery

**Discover Current Account:**

Run AWS CLI command to get current account information:

```bash
aws sts get-caller-identity
```

This returns the current account ID and ARN. Extract the account ID from the response.

**Discover Management Account:**

Run AWS CLI command to get organization information:

```bash
aws organizations describe-organization
```

This returns organization details including the management account ID. If the command fails with "AccessDeniedException", the user may not have Organizations permissions or may not be in the management account.

**Handle different scenarios:**

1. **Success - User is in management account:**
   - Extract management account ID from the organization details
   - Confirm: "I found that you're currently in the management account (ID: {account_id}). Is this correct?"

2. **Success - User is in member account:**
   - Extract management account ID from the organization details
   - Show current account: "You're currently in account {current_account_id}"
   - Show management account: "Your management account is {management_account_id}"
   - Confirm: "Is this correct?"

3. **Failure - No Organizations access:**
   - Inform user: "I don't have permissions to access AWS Organizations. This could mean:"
     - "You're not in the management account and don't have cross-account Organizations read access"
     - "Your credentials don't have the required permissions"
   - Ask: "Would you like to provide the management account ID manually, or should we try with different credentials?"

**Discover Member Accounts:**

If Organizations access is available, list all accounts:

```bash
aws organizations list-accounts
```

This returns all accounts in the organization with their IDs, names, and status.

**Parse and categorize accounts:**

1. Show the user all accounts found:
   ```
   I found the following accounts in your organization:

   Management Account:
   - {name} ({account_id})

   Member Accounts:
   - {name} ({account_id})
   - {name} ({account_id})
   - ...
   ```

2. Ask user to identify special accounts:
   - "Which account is your audit/security account? (Look for names like 'audit', 'security', 'security-tooling')"
   - "Which account is your log archive account? (Look for names like 'log-archive', 'logging', 'logs')"

3. If account names are obvious (contain "audit", "log", "security", etc.), suggest them:
   - "I see an account named 'Security-Audit' ({account_id}). Is this your audit account?"
   - "I see an account named 'Log-Archive' ({account_id}). Is this your log archive account?"

**Proceed to Step 1c (Gather Remaining Information) after account IDs are confirmed.**

---

### Step 1b: Manual Entry

**Required Information:**

1. **Management Account ID**
   - Ask: "What is your AWS Organizations management account ID?"
   - Format: 12-digit AWS account ID (e.g., "123456789012")
   - Purpose: Used for checks that validate management account configurations

2. **Audit Account ID**
   - Ask: "What is your audit/security account ID?"
   - Format: 12-digit AWS account ID
   - Purpose: Required for checks that validate centralized security tooling (GuardDuty, SecurityHub, etc.)

3. **Log Archive Account ID**
   - Ask: "What is your log archive account ID?"
   - Format: 12-digit AWS account ID
   - Purpose: Required for checks that validate centralized logging (CloudTrail, etc.)

**Proceed to Step 1c (Gather Remaining Information).**

---

### Step 1c: Gather Remaining Information

**Continue gathering the remaining required information:**

4. **AWS Profile Name**
   - Ask: "What AWS CLI profile should SRA Verify use? (You'll configure this in the MCP settings)"
   - Format: AWS CLI profile name (e.g., "default", "production", "sra-verify")
   - Purpose: The AWS profile that will be used to authenticate with AWS and assume roles into other accounts
   - Note: This profile should have permissions to assume the cross-account role
   - Default: If not specified, AWS SDK will use default credential chain

5. **Cross-Account Role ARN**
   - Ask: "What IAM role should SRA Verify assume to scan accounts? Please provide the full role ARN."
   - Format: Full ARN (e.g., "arn:aws:iam::123456789012:role/SRAVerifyRole")
   - Purpose: Role that SRA Verify will assume to perform cross-account checks
   - Note: This role should exist in all accounts with permissions to read security service configurations

6. **Primary Regions**
   - Ask: "What AWS regions do you primarily use? (e.g., us-east-1, us-west-2)"
   - Format: Comma-separated list of region codes
   - Purpose: Default regions to scan (can be overridden to scan all regions when needed)
   - Common examples: "us-east-1", "us-east-1,us-west-2", "us-east-1,eu-west-1,ap-southeast-1"
   - **Offer automatic discovery:** "Would you like me to detect which regions you're actively using by checking for resources?"

**If user wants automatic region discovery:**

Run AWS CLI command to list regions with resources:

```bash
aws ec2 describe-regions --all-regions --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output text
```

This shows all enabled regions. Then check for active resources in each region:

```bash
# Check for EC2 instances
aws ec2 describe-instances --region {region} --query 'Reservations[].Instances[].InstanceId' --output text

# Check for VPCs (good indicator of active regions)
aws ec2 describe-vpcs --region {region} --query 'Vpcs[?IsDefault==`false`].VpcId' --output text
```

Suggest regions where resources are found:
"I found active resources in these regions: {regions}. Would you like to use these as your primary regions?"

**Optional Information:**

7. **Application Account IDs** (optional)
   - If member accounts were discovered automatically, show the list and ask: "Would you like to track any specific application accounts? I can include them in your configuration."
   - If entered manually, ask: "Do you have specific application account IDs you want to track? (optional - you can add these later)"
   - Format: Comma-separated list of 12-digit account IDs
   - Purpose: Specific application accounts to validate
   - Note: This is optional - users can provide account IDs when running checks

---

### Step 2: Validate Information

**Before creating the configuration file, confirm the information with the user:**

Show them a summary:
```
Let me confirm your AWS environment details:

Management Account ID: {management_account_id}
Audit Account ID: {audit_account_id}
Log Archive Account ID: {log_archive_account_id}
AWS Profile Name: {profile_name}
Cross-Account Role ARN: {role_arn}
Primary Regions: {regions}
{if application accounts provided:}
Application Accounts: {application_account_ids}

Is this correct?
```

If they confirm, proceed to Step 3.
If they need to make changes, ask what needs to be corrected and update accordingly.

### Step 3: Create Environment Configuration File

**Create a steering file in the workspace with their environment details:**

Create the file at: `.kiro/steering/sra-verify-environment.md`

**File content template:**

```markdown
# SRA Verify Environment Configuration

This file contains your AWS environment configuration for SRA Verify checks.

**Created:** {current_date}
**Last Updated:** {current_date}

---

## AWS Account Information

### Management Account
- **Account ID:** {management_account_id}
- **Purpose:** AWS Organizations management account
- **Used for:** Management account configuration checks

### Audit Account
- **Account ID:** {audit_account_id}
- **Purpose:** Centralized security tooling and findings
- **Used for:** GuardDuty, SecurityHub, and other security service checks

### Log Archive Account
- **Account ID:** {log_archive_account_id}
- **Purpose:** Centralized logging destination
- **Used for:** CloudTrail and logging configuration checks

{if application accounts provided:}
### Application Accounts
{for each account:}
- **Account ID:** {account_id}
{end for}

---

## AWS Authentication

### Profile Name
```
{profile_name}
```

**Environment Variable:** `AWS_PROFILE={profile_name}` (configured in powers/sra-verify/mcp.json)

**Purpose:** This AWS CLI profile is used to authenticate with AWS and assume roles into other accounts.

**Configuration:**
- Configured in `powers/sra-verify/mcp.json` by replacing the placeholder "SRA_VERIFY_MCP_PROFILE_NAME" with your profile name
- Ensure this profile is configured in your `~/.aws/credentials` and `~/.aws/config` files

---

## Cross-Account Access

### Role ARN
```
{role_arn}
```

**Purpose:** This role is assumed by SRA Verify to perform cross-account security checks.

**Required Permissions:** The role should have read-only permissions for:
- GuardDuty
- SecurityHub
- CloudTrail
- IAM (read-only)
- CloudWatch
- Config
- Organizations (if checking from management account)
- Other AWS security services being validated

**Trust Relationship:** The role should trust your default AWS credentials to assume it.

---

## Default Regions

**Primary Regions:**
```
{regions}
```

These regions will be scanned by default. You can override this to scan all regions by specifying `region="all"` when running checks.

---

## Quick Reference Commands

### Discovery Commands

**List all available services:**
```
Use list_services tool
```

**List checks for a specific service:**
```
Use list_checks_by_service tool with service="GuardDuty"
(Replace "GuardDuty" with any service name)
```

**List checks by account type:**
```
Use list_checks_by_account_type tool with account_type="audit"
(Options: "management", "audit", "log-archive", "application", "all")
```

### Running Checks with Your Configuration

**Run a check with your environment settings:**
```
Use run_check tool with:
  check_id="{check_id}"
  audit_accounts=["{audit_account_id}"]
  log_archive_accounts=["{log_archive_account_id}"]
  role_arn="{role_arn}"
  region="{first_region}"
```

**Example - GuardDuty Check:**
```
Use run_check tool with:
  check_id="SRA-GUARDDUTY-01"
  audit_accounts=["{audit_account_id}"]
  role_arn="{role_arn}"
  region="{first_region}"
```

**Scan all regions instead of primary regions:**
```
Use run_check tool with:
  check_id="{check_id}"
  audit_accounts=["{audit_account_id}"]
  log_archive_accounts=["{log_archive_account_id}"]
  role_arn="{role_arn}"
  region="all"
```

---

## Updating This Configuration

To update your environment configuration:
1. Edit this file directly: `.kiro/steering/sra-verify-environment.md`
2. Or ask the agent to update specific values
3. Update the "Last Updated" date when making changes

---

## Next Steps

Now that your environment is configured, you can:

1. **Discover available checks:**
   - List services: `list_services`
   - List checks by service: `list_checks_by_service`
   - List checks by account type: `list_checks_by_account_type`

2. **Run your first check:**
   - Describe a check: `describe_check` with a check_id
   - Run the check using the commands above with your configuration

3. **Explore workflows:**
   - Post-deployment validation
   - Continuous compliance monitoring
   - Pre-audit preparation
   - Troubleshooting security issues

Refer to the main POWER.md documentation for detailed workflow examples.
```

### Step 4: Update MCP Configuration

**After creating the configuration file, help the user update the power's mcp.json:**

Tell the user:
```
To use SRA Verify with your configured profile, you need to update the power's MCP configuration.

I'll update the mcp.json file in the sra-verify power to use your AWS profile: {profile_name}
```

**Update the power's MCP configuration:**

1. Open the file `powers/sra-verify/mcp.json`
2. Find the placeholder text `SRA_VERIFY_MCP_PROFILE_NAME` in the `AWS_PROFILE` value
3. Replace `SRA_VERIFY_MCP_PROFILE_NAME` with the actual profile name

**Example - Before:**
```json
{
  "mcpServers": {
    "awslabs.sraverify-mcp-server": {
      "env": {
        "AWS_PROFILE": "SRA_VERIFY_MCP_PROFILE_NAME"
      }
    }
  }
}
```

**Example - After (if profile is "default"):**
```json
{
  "mcpServers": {
    "awslabs.sraverify-mcp-server": {
      "env": {
        "AWS_PROFILE": "default"
      }
    }
  }
}
```

After updating, tell the user:
```
✅ MCP configuration updated!

I've replaced "SRA_VERIFY_MCP_PROFILE_NAME" with "{profile_name}" in powers/sra-verify/mcp.json.

The SRA Verify MCP server will now use this profile to authenticate with AWS.

Note: The MCP server will automatically reconnect with the new configuration. If you need to manually reconnect, you can do so from the MCP Server view in the Kiro feature panel.
```

---

### Step 5: Confirm Creation and Next Steps

**Tell the user:**

```
✅ Environment configuration created!

Your AWS environment details have been saved to:
.kiro/steering/sra-verify-environment.md

This file contains:
- Your account IDs (management, audit, log-archive)
- AWS profile name (configured in powers/sra-verify/mcp.json)
- Cross-account role ARN
- Primary regions to scan
- Quick reference commands pre-filled with your configuration

You can now:
1. Run checks using the pre-configured commands in the file
2. Reference this file anytime you need your environment details
3. Update the file if your environment changes

Would you like to run your first check? I can help you:
- Discover available checks
- Run a specific check with your configuration
- Validate a particular security service
```

---

## Important Guidelines for Agents

### Automatic Discovery
- **Always offer automatic discovery first** - It's faster and more accurate than manual entry
- **Handle AWS CLI errors gracefully** - If commands fail, fall back to manual entry
- **Explain what you're doing** - Tell users which commands you're running and why
- **Parse output carefully** - Extract account IDs and names from JSON responses
- **Suggest obvious matches** - If account names contain "audit", "log", "security", highlight them
- **Confirm discoveries** - Always confirm automatically discovered information with the user
- **Respect user choice** - If they prefer manual entry, don't insist on automatic discovery

### AWS CLI Commands
- **Check for AWS CLI** - Verify AWS CLI is installed before attempting discovery
- **Handle missing permissions** - If Organizations commands fail, explain why and offer alternatives
- **Use appropriate regions** - Some commands need to run in specific regions (e.g., us-east-1 for Organizations)
- **Format output properly** - Use `--output json` for parsing, `--output text` for simple lists
- **Show command output** - Let users see what was discovered

### Information Gathering
- **Ask questions naturally** - Don't present a form, have a conversation
- **Validate format** - Ensure account IDs are 12 digits, ARNs are properly formatted
- **Explain purpose** - Help users understand why each piece of information is needed
- **Provide examples** - Show format examples for each field
- **Be patient** - Users may need to look up account IDs or role ARNs

### File Creation
- **Use workspace path** - Create file at `.kiro/steering/sra-verify-environment.md`
- **Include all gathered information** - Don't leave placeholders
- **Add current date** - Use actual date when creating the file
- **Format consistently** - Use the template structure provided
- **Make it actionable** - Include ready-to-use commands with their actual values

### MCP Configuration
- **Update power's mcp.json** - Replace placeholder in `powers/sra-verify/mcp.json`
- **Find the placeholder** - Look for `"AWS_PROFILE": "SRA_VERIFY_MCP_PROFILE_NAME"`
- **Replace with actual profile** - Replace `SRA_VERIFY_MCP_PROFILE_NAME` with the profile name (keep the quotes)
- **Example** - Change `"AWS_PROFILE": "SRA_VERIFY_MCP_PROFILE_NAME"` to `"AWS_PROFILE": "default"`
- **Explain reconnection** - Tell users the MCP server will automatically reconnect

### After Creation
- **Confirm success** - Tell user where the file was created
- **Explain benefits** - How this file helps them use SRA Verify
- **Offer next steps** - Guide them to run their first check
- **Be available** - Offer to help with first check execution

### Updating Configuration
- **Easy updates** - Users can ask you to update specific values
- **Preserve structure** - Keep the file format consistent when updating
- **Update timestamp** - Change "Last Updated" date when modifying
- **Confirm changes** - Show what was changed after updates

---

## Example Onboarding Conversations

### Example 1: Automatic Discovery (Successful)

**Agent:** "Let's get SRA Verify configured for your AWS environment. I can help you discover your AWS account information automatically using AWS CLI commands. Would you like me to identify your accounts and organization structure automatically, or would you prefer to provide the information manually?"

**User:** "Try automatic discovery"

**Agent:** *Runs `aws sts get-caller-identity` and `aws organizations describe-organization`*

"Great! I found your AWS organization. You're currently in the management account (ID: 123456789012). Let me list all your member accounts..."

**Agent:** *Runs `aws organizations list-accounts`*

"I found the following accounts in your organization:

Management Account:
- Production-Management (123456789012)

Member Accounts:
- Security-Audit (234567890123)
- Log-Archive (345678901234)
- App-Production (456789012345)
- App-Development (567890123456)

I see accounts named 'Security-Audit' and 'Log-Archive'. Are these your audit and log archive accounts?"

**User:** "Yes, that's correct"

**Agent:** "Perfect! Now, what AWS CLI profile should SRA Verify use to authenticate? I'll configure this in your MCP settings."

**User:** "default"

**Agent:** "Great. Now I need the IAM role ARN that SRA Verify should assume to scan accounts. This role should exist in all accounts with read permissions for security services."

**User:** "arn:aws:iam::123456789012:role/SRAVerifyRole"

**Agent:** "Great. Would you like me to detect which AWS regions you're actively using, or would you prefer to specify them manually?"

**User:** "Detect them"

**Agent:** *Runs region detection commands*

"I found active resources in these regions: us-east-1, us-west-2. Would you like to use these as your primary regions?"

**User:** "Yes"

**Agent:** "Perfect! Let me confirm your configuration:

Management Account ID: 123456789012
Audit Account ID: 234567890123
Log Archive Account ID: 345678901234
AWS Profile Name: default
Cross-Account Role ARN: arn:aws:iam::123456789012:role/SRAVerifyRole
Primary Regions: us-east-1, us-west-2

Is this correct?"

**User:** "Yes"

**Agent:** *Creates .kiro/steering/sra-verify-environment.md with the configuration*

"✅ Environment configuration created!

Now I'll update the power's MCP configuration to use your AWS profile: default"

**Agent:** *Opens powers/sra-verify/mcp.json and replaces "SRA_VERIFY_MCP_PROFILE_NAME" with "default"*

"✅ MCP configuration updated!

I've replaced "SRA_VERIFY_MCP_PROFILE_NAME" with "default" in powers/sra-verify/mcp.json. The SRA Verify MCP server will now use this profile to authenticate with AWS.

Your AWS environment details have been saved to .kiro/steering/sra-verify-environment.md. Would you like to run your first check?"

---

### Example 2: Manual Entry (User Preference)

**Agent:** "Let's get SRA Verify configured for your AWS environment. I can help you discover your AWS account information automatically using AWS CLI commands, or you can provide the information manually. Which would you prefer?"

**User:** "I'll provide it manually"

**User:** "I'll provide it manually"

**Agent:** "No problem! Let's start with your AWS Organizations management account ID."

**User:** "123456789012"

**Agent:** "Got it. What is your audit/security account ID where centralized security tooling runs?"

**User:** "234567890123"

**Agent:** "Perfect. And your log archive account ID where CloudTrail logs are centralized?"

**User:** "345678901234"

**Agent:** "Great. What AWS CLI profile should SRA Verify use to authenticate? I'll configure this in your MCP settings."

**User:** "production"

**Agent:** "Perfect. Now I need the IAM role ARN that SRA Verify should assume to scan accounts. This role should exist in all accounts with read permissions for security services."

**User:** "arn:aws:iam::123456789012:role/SRAVerifyRole"

**Agent:** "Excellent. What AWS regions do you primarily use? For example: us-east-1, us-west-2"

**User:** "us-east-1, us-west-2"

**Agent:** "Perfect! Let me confirm your configuration:

Management Account ID: 123456789012
Audit Account ID: 234567890123
Log Archive Account ID: 345678901234
AWS Profile Name: production
Cross-Account Role ARN: arn:aws:iam::123456789012:role/SRAVerifyRole
Primary Regions: us-east-1, us-west-2

Is this correct?"

**User:** "Yes"

**Agent:** *Creates .kiro/steering/sra-verify-environment.md with the configuration*

"✅ Environment configuration created!

Now I'll update the power's MCP configuration to use your AWS profile: production"

**Agent:** *Opens powers/sra-verify/mcp.json and replaces "SRA_VERIFY_MCP_PROFILE_NAME" with "production"*

"✅ MCP configuration updated!

I've replaced "SRA_VERIFY_MCP_PROFILE_NAME" with "production" in powers/sra-verify/mcp.json. The SRA Verify MCP server will now use this profile to authenticate with AWS.

Your AWS environment details have been saved to .kiro/steering/sra-verify-environment.md. Would you like to run your first check?"

---

### Example 3: Automatic Discovery with Fallback (Partial Permissions)

**Agent:** "Let's get SRA Verify configured for your AWS environment. I can help you discover your AWS account information automatically. Should I try automatic discovery?"

**User:** "Yes please"

**Agent:** *Runs `aws sts get-caller-identity`* - Success
*Runs `aws organizations describe-organization`* - AccessDeniedException

"I can see you're currently in account 456789012345, but I don't have permissions to access AWS Organizations. This likely means you're in a member account without cross-account Organizations access.

Would you like to:
1. Provide the management account ID manually
2. Switch to credentials with Organizations access and try again"

**User:** "I'll provide it manually. Management account is 123456789012"

**Agent:** "Got it. Since I can't list all accounts automatically, could you also provide your audit and log archive account IDs?"

*Continues with manual entry for remaining information...*
