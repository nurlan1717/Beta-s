# Phishing Awareness Lab - Complete Guide

## Overview

The **Phishing Awareness Lab** is a comprehensive security awareness training module integrated into the RansomRun platform. It allows security teams to create, launch, and track realistic phishing simulation campaigns to train employees on recognizing and reporting phishing attempts.

## ⚠️ Safety Features (Built-in)

All phishing simulations include multiple safety layers:

1. **[SIMULATION] Banner**: Every email includes a visible training marker
2. **Allowlisted Domains Only**: Only pre-approved email domains can be used
3. **No External SMTP**: Emails are delivered IN_APP or to local mail sink only
4. **No Credential Collection**: Templates never request passwords or MFA codes
5. **Internal Links Only**: All tracking links redirect to internal RansomRun routes
6. **No Malicious Attachments**: Attachment simulations are safe placeholders only

## Features

### 1. Campaign Management
- Create unlimited phishing campaigns
- Choose from 10 pre-built safe templates
- Import recipients via CSV
- Track campaign status (DRAFT → RUNNING → ENDED)

### 2. Email Templates (10 Built-in)

| Template | Category | Description |
|----------|----------|-------------|
| `password_reset_it` | Password Reset | IT department password reset notice |
| `invoice_pending` | Invoice | Pending invoice notification |
| `shared_document` | Shared Document | Document sharing notification |
| `package_delivery` | Delivery | Package delivery update |
| `hr_policy_update` | HR | Company policy update |
| `meeting_invite` | Meeting | Meeting invitation |
| `security_alert` | Security | Unusual login activity alert |
| `voicemail_notification` | Voicemail | New voicemail message |
| `software_update` | Software | Software update notification |
| `employee_survey` | Survey | Employee satisfaction survey |

### 3. Delivery Modes

#### IN_APP Mode (Default - Recommended)
- Messages appear in the in-app inbox
- No external email infrastructure needed
- 100% safe and contained
- Perfect for training exercises

#### MAIL_SINK Mode (Advanced)
- Sends to local mail server (MailHog/smtp4dev/Papercut)
- Requires local mail sink running on localhost
- Blocked from sending to external SMTP servers
- Useful for testing with real email clients

### 4. Tracking & Metrics

The platform automatically tracks:
- **SENT**: Message delivered to recipient
- **OPENED**: Recipient viewed the message
- **CLICKED**: Recipient clicked the phishing link
- **REPORTED**: Recipient reported the message as phishing

Metrics calculated:
- Open Rate (% of recipients who opened)
- Click Rate (% of recipients who clicked)
- Report Rate (% of recipients who reported)

### 5. Safe Landing Page

When a user clicks a phishing link, they are redirected to a training landing page that:
- Explains this was a simulation
- Shows what red flags they should have noticed
- Provides security awareness tips
- Optionally triggers a safe ransomware simulation (rename-only)

---

## Quick Start Guide

### Step 1: Enable Phishing Lab

The feature is already enabled in your `.env` file:

```bash
PHISHING_SIM_ENABLED=true
PHISHING_DELIVERY_MODE=IN_APP
ALLOWLIST_DOMAINS=lab.local,example.local,test.local,ransomrun.local,training.local
```

### Step 2: Access the Phishing Lab

1. Start the RansomRun backend server (if not already running)
2. Navigate to: `http://localhost:8000/phishing`
3. You'll see the campaign dashboard

### Step 3: Create Your First Campaign

1. Click **"New Campaign"**
2. Fill in campaign details:
   - **Name**: "Q1 Security Awareness Training"
   - **Description**: "Testing employee awareness of phishing emails"
   - **Template**: Select "IT Password Reset Notice"
   - **Delivery Mode**: IN_APP (recommended)
   - **Scenario** (optional): Link to a safe ransomware simulation

3. Click **"Create Campaign"**

### Step 4: Add Recipients

#### Option A: Manual Entry
1. In the campaign detail page, click **"Add Recipient"**
2. Enter:
   - Display Name: "John Doe"
   - Email: "john.doe@lab.local"
   - Department: "IT"
3. Click **"Add"**

#### Option B: CSV Import
1. Create a CSV file with headers: `display_name,email,department`
   ```csv
   display_name,email,department
   John Doe,john.doe@lab.local,IT
   Jane Smith,jane.smith@lab.local,HR
   Bob Johnson,bob.johnson@lab.local,Finance
   ```

2. Click **"Import Recipients"**
3. Upload the CSV file
4. Review import results (accepted/rejected)

**Important**: Only emails with allowlisted domains will be accepted.

### Step 5: Launch Campaign

1. Review your campaign settings and recipients
2. Click **"Launch Campaign"**
3. The system will:
   - Generate personalized messages for each recipient
   - Create unique tracking links
   - Deliver messages (IN_APP or MAIL_SINK)
   - Mark campaign as RUNNING

### Step 6: Monitor Results

#### View Campaign Dashboard
Navigate to: `http://localhost:8000/phishing/dashboard`

You'll see:
- Total campaigns
- Overall open/click/report rates
- Per-campaign statistics
- Timeline of events

#### View Campaign Details
Click on a campaign to see:
- Recipient list with individual tracking status
- Who opened, clicked, or reported
- Timestamps for each event
- Real-time metrics

### Step 7: Test as a Recipient

#### View In-App Inbox
1. Navigate to: `http://localhost:8000/phishing/inbox`
2. Select a recipient email from the dropdown
3. You'll see all messages sent to that recipient
4. Click a message to open it (marks as OPENED)
5. Click the link in the message (marks as CLICKED)
6. You'll be redirected to the training landing page

#### Report a Message
In the message view, click **"Report as Phishing"** button
- Marks message as REPORTED
- Shows success message
- Increases report rate metric

---

## Advanced Configuration

### Using MAIL_SINK Mode with MailHog

MailHog is a local email testing tool that captures SMTP traffic.

#### 1. Install MailHog

**Windows (via Chocolatey)**:
```powershell
choco install mailhog
```

**macOS (via Homebrew)**:
```bash
brew install mailhog
```

**Linux**:
```bash
# Download binary
wget https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64
chmod +x MailHog_linux_amd64
sudo mv MailHog_linux_amd64 /usr/local/bin/mailhog
```

#### 2. Start MailHog

```bash
mailhog
```

MailHog will start:
- SMTP Server: `localhost:1025`
- Web UI: `http://localhost:8025`

#### 3. Configure RansomRun

Update `.env`:
```bash
PHISHING_DELIVERY_MODE=MAIL_SINK
ENABLE_LOCAL_MAIL_SINK=true
MAILHOG_HOST=localhost
MAILHOG_PORT=1025
```

#### 4. Restart RansomRun Backend

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 5. Launch Campaign

When you launch a campaign with MAIL_SINK mode:
- Emails are sent to MailHog
- View them at `http://localhost:8025`
- Test with real email clients (Outlook, Thunderbird, etc.)

---

## Linking Phishing to Ransomware Simulations

You can automatically trigger a safe ransomware simulation when a user clicks a phishing link.

### Setup

1. **Create a Safe Scenario**:
   - Navigate to Scenarios
   - Create or select a scenario with:
     - Category: "fake" or "crypto"
     - Config: Set `destructive: false` and `rename_only: true`

2. **Link to Campaign**:
   - When creating a campaign, select the scenario from dropdown
   - Map recipients to registered hosts (optional)

3. **How It Works**:
   - User clicks phishing link
   - System marks message as CLICKED
   - If scenario_id and host_id are set:
     - Creates a new simulation Run
     - Assigns task to the agent
     - Agent executes safe simulation (rename files only)
   - User is redirected to landing page

### Example Safe Scenario Config

```json
{
  "target_dir": "C:\\RansomTest",
  "file_extensions": [".txt", ".docx"],
  "max_files": 5,
  "destructive": false,
  "rename_only": true,
  "ransom_note": "TRAINING_NOTE.txt",
  "note_content": "[SIMULATION] This is a training exercise."
}
```

---

## API Reference

### REST Endpoints

#### Create Campaign
```http
POST /api/phishing/campaigns
Content-Type: application/json

{
  "name": "Q1 Training",
  "description": "Security awareness campaign",
  "template_key": "password_reset_it",
  "delivery_mode": "IN_APP",
  "scenario_id": 1
}
```

#### Import Recipients
```http
POST /api/phishing/recipients/import
Content-Type: multipart/form-data

campaign_id: 1
file: recipients.csv
```

#### Launch Campaign
```http
POST /api/phishing/campaigns/{campaign_id}/launch
```

#### Get Campaign Stats
```http
GET /api/phishing/campaigns/{campaign_id}/stats

Response:
{
  "total_messages": 10,
  "sent": 10,
  "opened": 7,
  "clicked": 3,
  "reported": 2,
  "open_rate": 70.0,
  "click_rate": 30.0,
  "report_rate": 20.0
}
```

#### Report Phishing
```http
POST /api/phishing/report/{message_id}

Response:
{
  "success": true,
  "message": "Thank you for reporting this phishing attempt!"
}
```

### Tracking Endpoints

#### Click Tracking
```http
GET /phishing/t/{token}
```
- Records CLICKED event
- Optionally triggers simulation
- Redirects to landing page

#### Message View (Opens)
```http
GET /phishing/message/{message_id}
```
- Records OPENED event
- Displays message content

---

## Security & Safety Controls

### Domain Allowlist

Only emails from allowlisted domains can be used:

```bash
ALLOWLIST_DOMAINS=lab.local,example.local,test.local,ransomrun.local,training.local
```

To add a domain:
1. Edit `.env` file
2. Add domain to comma-separated list
3. Restart backend server

### SMTP Safety Checks

The system enforces:
- **No public SMTP servers**: Gmail, Outlook, Yahoo are blocked
- **Localhost only**: MAIL_SINK mode only connects to 127.0.0.1 or localhost
- **Port validation**: Only connects to ports 1025, 1026, 2525 (common mail sink ports)

### Template Safety

All templates include:
- `[SIMULATION]` banner in subject and body
- Training disclaimer at bottom
- No password/credential requests
- No executable attachments
- Educational messaging

---

## Troubleshooting

### Issue: "Phishing simulation is disabled"

**Solution**: Check `.env` file:
```bash
PHISHING_SIM_ENABLED=true
```

### Issue: "Email domain not allowed"

**Solution**: Add domain to allowlist in `.env`:
```bash
ALLOWLIST_DOMAINS=lab.local,example.local,yourdomain.local
```

### Issue: "Mail sink delivery is disabled"

**Solution**: Enable in `.env`:
```bash
ENABLE_LOCAL_MAIL_SINK=true
```

### Issue: MailHog not receiving emails

**Checklist**:
1. MailHog is running: `mailhog`
2. Check web UI: `http://localhost:8025`
3. Verify `.env` settings:
   ```bash
   MAILHOG_HOST=localhost
   MAILHOG_PORT=1025
   ```
4. Restart RansomRun backend

### Issue: Tracking links not working

**Solution**: Ensure backend is accessible at the correct URL. Tracking links use the request base URL.

---

## Best Practices

### 1. Start with IN_APP Mode
- Easiest to set up
- No external dependencies
- Perfect for initial testing

### 2. Use Realistic Scenarios
- Choose templates that match your organization
- Customize sender names
- Use appropriate departments

### 3. Educate, Don't Punish
- Use landing page to teach
- Explain red flags
- Provide resources

### 4. Track Progress Over Time
- Run campaigns quarterly
- Compare metrics
- Identify improvement areas

### 5. Combine with Simulations
- Link phishing to safe ransomware scenarios
- Show real-world impact
- Reinforce training

---

## Example Workflows

### Workflow 1: Basic Awareness Training

1. Create campaign: "Password Reset Awareness"
2. Use template: `password_reset_it`
3. Add 10-20 recipients from CSV
4. Launch in IN_APP mode
5. Monitor open/click/report rates
6. Review results after 1 week

### Workflow 2: Department-Specific Training

1. Create campaign: "Finance Department - Invoice Phishing"
2. Use template: `invoice_pending`
3. Import only Finance department recipients
4. Launch campaign
5. Compare Finance metrics to other departments

### Workflow 3: Advanced Simulation

1. Create safe ransomware scenario (rename-only)
2. Create campaign linked to scenario
3. Map recipients to registered hosts
4. Launch campaign
5. When user clicks:
   - Phishing link tracked
   - Safe simulation triggered on their host
   - Files renamed (reversible)
   - User sees training landing page
6. Review both phishing and simulation metrics

---

## Database Schema

### PhishingCampaign
- `id`: Primary key
- `name`: Campaign name
- `description`: Campaign description
- `template_key`: Template identifier
- `status`: DRAFT | RUNNING | PAUSED | ENDED
- `delivery_mode`: IN_APP | MAIL_SINK
- `scenario_id`: Optional linked scenario
- `created_at`, `started_at`, `ended_at`: Timestamps

### PhishingRecipient
- `id`: Primary key
- `campaign_id`: Foreign key to campaign
- `display_name`: Recipient name
- `email`: Recipient email
- `department`: Department (optional)
- `host_id`: Linked host for simulations (optional)
- `allowlisted`: Boolean

### PhishingMessage
- `id`: Primary key
- `campaign_id`: Foreign key to campaign
- `recipient_id`: Foreign key to recipient
- `subject`: Email subject
- `body_html`: HTML body
- `body_text`: Plain text body
- `tracking_token`: Unique tracking token
- `status`: PENDING | SENT
- `is_opened`, `is_clicked`, `is_reported`: Boolean flags
- `sent_at`, `opened_at`, `clicked_at`, `reported_at`: Timestamps

### PhishingEvent
- `id`: Primary key
- `message_id`: Foreign key to message
- `event_type`: SENT | OPENED | CLICKED | REPORTED
- `timestamp`: Event timestamp
- `meta_json`: Additional metadata (IP, user agent, etc.)

---

## Metrics & Reporting

### Campaign-Level Metrics
- Total messages sent
- Open rate (%)
- Click rate (%)
- Report rate (%)

### Overall Statistics
- Total campaigns
- Active campaigns
- Total messages across all campaigns
- Average open/click/report rates

### Event Timeline
- Chronological list of all events
- Filter by campaign, recipient, or event type
- Export to CSV for analysis

---

## Integration with RansomRun Features

### 1. Host Management
- Link recipients to registered hosts
- Trigger simulations on specific machines
- Track per-host phishing susceptibility

### 2. Scenario Library
- Use existing safe scenarios
- Create phishing-specific scenarios
- Combine awareness training with technical simulation

### 3. Metrics & Reporting
- Unified dashboard
- Compare phishing vs. ransomware metrics
- Comprehensive incident reports

### 4. User Skill Tracking
- Track individual user performance
- Identify training needs
- Generate SOC CV profiles

---

## Support & Resources

### Documentation
- Main README: `README.md`
- API Documentation: `http://localhost:8000/docs`
- This Guide: `PHISHING_LAB_README.md`

### Code Structure
```
app/
├── models.py                          # Database models
├── crud_phishing.py                   # CRUD operations
├── routers/
│   └── phishing.py                    # API routes
├── services/
│   └── phishing_templates.py          # Email templates
└── templates/
    ├── phishing_campaigns.html        # Campaign list
    ├── phishing_campaign_form.html    # Create/edit campaign
    ├── phishing_dashboard.html        # Metrics dashboard
    ├── phishing_inbox.html            # In-app inbox
    ├── phishing_message.html          # Message view
    └── phishing_landing.html          # Training landing page
```

### Environment Variables
```bash
PHISHING_SIM_ENABLED=true
PHISHING_DELIVERY_MODE=IN_APP
ENABLE_LOCAL_MAIL_SINK=false
MAILHOG_HOST=localhost
MAILHOG_PORT=1025
ALLOWLIST_DOMAINS=lab.local,example.local,test.local,ransomrun.local,training.local
```

---

## Conclusion

The Phishing Awareness Lab provides a comprehensive, safe, and effective platform for security awareness training. By combining realistic phishing simulations with detailed tracking and optional ransomware scenarios, organizations can significantly improve their security posture and employee awareness.

**Remember**: The goal is education, not punishment. Use the metrics to identify training opportunities and celebrate improvements.

For questions or issues, refer to the troubleshooting section or check the API documentation at `/docs`.

---

**Version**: 1.0  
**Last Updated**: December 2025  
**Platform**: RansomRun v3.0
