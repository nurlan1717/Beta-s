# Phishing Lab - Quick Test Guide

## 5-Minute Test (IN_APP Mode)

### Prerequisites
- RansomRun backend server running on `http://localhost:8000`
- Phishing Lab enabled in `.env` (already configured)

### Test Steps

#### 1. Access Phishing Lab
```
http://localhost:8000/phishing
```

You should see the campaign dashboard with statistics.

#### 2. Create a Test Campaign

1. Click **"New Campaign"** button
2. Fill in the form:
   - **Name**: "Test Campaign 1"
   - **Description**: "Testing phishing awareness"
   - **Template**: Select "IT Password Reset Notice"
   - **Delivery Mode**: IN_APP (default)
   - Leave Scenario blank for now
3. Click **"Create Campaign"**

#### 3. Add Test Recipients

**Option A - Manual (Quick)**:
1. In the campaign page, scroll to "Recipients" section
2. Click **"Add Recipient"**
3. Enter:
   - Display Name: "Test User"
   - Email: "test.user@lab.local"
   - Department: "IT"
4. Click **"Add"**

**Option B - CSV Import**:
1. Create `test_recipients.csv`:
   ```csv
   display_name,email,department
   Alice Johnson,alice.johnson@lab.local,HR
   Bob Smith,bob.smith@lab.local,Finance
   Carol White,carol.white@lab.local,IT
   ```
2. Click **"Import Recipients"**
3. Upload the CSV file
4. Verify import results

#### 4. Launch Campaign

1. Click **"Launch Campaign"** button
2. Confirm the action
3. Wait for success message
4. Campaign status changes to "RUNNING"

#### 5. View In-App Inbox

1. Navigate to: `http://localhost:8000/phishing/inbox`
2. Select email from dropdown: "test.user@lab.local"
3. You should see the phishing message in the inbox
4. Click on the message to open it

**Expected Result**: Message is marked as OPENED

#### 6. Click the Phishing Link

1. In the opened message, click the blue **"Verify Account"** button
2. You'll be redirected to the training landing page

**Expected Results**:
- Message is marked as CLICKED
- Landing page shows:
  - "[SIMULATION]" banner
  - Explanation of the phishing attempt
  - Red flags to watch for
  - Security tips

#### 7. Report as Phishing

1. Go back to the inbox
2. Open the message again
3. Click **"Report as Phishing"** button

**Expected Result**: Message is marked as REPORTED

#### 8. View Campaign Metrics

1. Navigate to: `http://localhost:8000/phishing/dashboard`
2. Or click on your campaign in the campaign list

**Expected Metrics**:
- Total Messages: 1 (or 3 if you used CSV)
- Sent: 1
- Opened: 1 (100%)
- Clicked: 1 (100%)
- Reported: 1 (100%)

---

## Advanced Test (With Ransomware Simulation)

### Prerequisites
- Agent registered and connected
- Safe scenario created

### Steps

#### 1. Create Safe Scenario

1. Navigate to: `http://localhost:8000/scenarios`
2. Click **"Create Custom Scenario"**
3. Fill in:
   - **Key**: "phishing_test_safe"
   - **Name**: "Phishing Test - Safe Rename"
   - **Category**: "fake"
   - **Config**:
     ```json
     {
       "target_dir": "C:\\RansomTest",
       "file_extensions": [".txt"],
       "max_files": 3,
       "destructive": false,
       "rename_only": true,
       "ransom_note": "TRAINING_NOTE.txt",
       "note_content": "[SIMULATION] This is a training exercise."
     }
     ```
4. Save scenario

#### 2. Create Campaign with Scenario Link

1. Create new campaign
2. Select the scenario you just created
3. Add recipients
4. **Important**: Map recipients to registered hosts
   - Edit recipient
   - Select a host from dropdown
   - Save

#### 3. Launch and Test

1. Launch campaign
2. View inbox and click phishing link
3. **Expected Results**:
   - Message marked as CLICKED
   - Ransomware simulation triggered on the host
   - Agent executes safe rename-only simulation
   - User redirected to landing page
   - Check agent logs for simulation execution

#### 4. Verify Simulation

1. Navigate to: `http://localhost:8000/runs`
2. You should see a new run created
3. Click on the run to see details
4. Check the host for renamed files (reversible)

---

## Testing MAIL_SINK Mode (Optional)

### Prerequisites
- MailHog installed and running

### Setup MailHog

**Start MailHog**:
```bash
mailhog
```

**Access MailHog Web UI**:
```
http://localhost:8025
```

### Configure RansomRun

Edit `app/.env`:
```bash
PHISHING_DELIVERY_MODE=MAIL_SINK
ENABLE_LOCAL_MAIL_SINK=true
MAILHOG_HOST=localhost
MAILHOG_PORT=1025
```

**Restart Backend**:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Test

1. Create campaign with MAIL_SINK delivery mode
2. Add recipients with allowlisted domains
3. Launch campaign
4. Check MailHog web UI at `http://localhost:8025`
5. You should see the phishing emails
6. Click tracking links in emails (they work from MailHog too!)

---

## API Testing (Using curl or Postman)

### Create Campaign
```bash
curl -X POST http://localhost:8000/api/phishing/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Test Campaign",
    "description": "Testing via API",
    "template_key": "password_reset_it",
    "delivery_mode": "IN_APP"
  }'
```

### Add Recipient
```bash
curl -X POST http://localhost:8000/api/phishing/campaigns/1/recipients \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "API Test User",
    "email": "api.test@lab.local",
    "department": "Engineering"
  }'
```

### Launch Campaign
```bash
curl -X POST http://localhost:8000/api/phishing/campaigns/1/launch
```

### Get Campaign Stats
```bash
curl http://localhost:8000/api/phishing/campaigns/1/stats
```

### Get Overall Stats
```bash
curl http://localhost:8000/api/phishing/stats
```

### List Templates
```bash
curl http://localhost:8000/api/phishing/templates
```

---

## Troubleshooting

### Issue: "Phishing simulation is disabled"
**Fix**: Check `app/.env`:
```bash
PHISHING_SIM_ENABLED=true
```

### Issue: "Email domain not allowed"
**Fix**: Add domain to allowlist in `app/.env`:
```bash
ALLOWLIST_DOMAINS=lab.local,example.local,test.local,yourdomain.local
```

### Issue: No messages in inbox
**Check**:
1. Campaign is launched (status = RUNNING)
2. Messages are marked as SENT
3. Correct email selected in inbox dropdown

### Issue: Tracking link doesn't work
**Check**:
1. Backend is running
2. Token is valid
3. Check browser console for errors

---

## Expected Results Summary

| Action | Expected Behavior |
|--------|-------------------|
| Create Campaign | Campaign appears in list with DRAFT status |
| Add Recipient | Recipient appears in campaign recipients list |
| Launch Campaign | Status changes to RUNNING, messages created |
| View Inbox | Messages appear for selected email |
| Open Message | Message marked as OPENED, timestamp recorded |
| Click Link | Message marked as CLICKED, redirect to landing page |
| Report Message | Message marked as REPORTED, success notification |
| View Dashboard | Metrics show open/click/report rates |

---

## Sample Test Data

### CSV File (test_recipients.csv)
```csv
display_name,email,department
Alice Johnson,alice.johnson@lab.local,HR
Bob Smith,bob.smith@lab.local,Finance
Carol White,carol.white@lab.local,IT
David Brown,david.brown@lab.local,Sales
Eve Davis,eve.davis@lab.local,Marketing
```

### Safe Scenario Config
```json
{
  "target_dir": "C:\\RansomTest",
  "file_extensions": [".txt", ".docx"],
  "max_files": 5,
  "destructive": false,
  "rename_only": true,
  "ransom_note": "TRAINING_NOTE.txt",
  "note_content": "[SIMULATION] This is a security awareness training exercise. Your files have been renamed but not encrypted. This demonstrates what could happen in a real ransomware attack. Contact IT for assistance."
}
```

---

## Next Steps

After successful testing:

1. **Create Real Campaigns**:
   - Use realistic recipient lists
   - Choose appropriate templates
   - Schedule campaigns quarterly

2. **Analyze Results**:
   - Review metrics
   - Identify high-risk users
   - Plan targeted training

3. **Integrate with Simulations**:
   - Link campaigns to safe scenarios
   - Demonstrate real-world impact
   - Reinforce training

4. **Export Data**:
   - Use API to export metrics
   - Create reports
   - Track progress over time

---

## Support

- Full Documentation: `PHISHING_LAB_README.md`
- API Docs: `http://localhost:8000/docs`
- Main README: `README.md`

**Test Duration**: 5-10 minutes for basic test, 15-20 minutes for advanced test with simulations.
