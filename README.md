# DevPulse — Full Data Flow (Beginner-Friendly Edition)

> **Scenario**: You push code to your GitHub repo. Let's trace what happens **step by step** until the dashboard shows "CODE_PUSH: username pushed 1 commit(s) to main".

---

## The Pizza Delivery Analogy 🍕

Before we start, here's the analogy we'll use throughout:

```
You (GitHub)         = A customer placing a pizza order (push event)
ngrok                = The delivery app (connects the outside world to the kitchen)
Django View          = The kitchen that receives and validates the order
Database             = The order logbook where every order is recorded
Signal               = An automatic bell that rings when a new order is written
WebSocket            = A walkie-talkie between the kitchen and the display board
Dashboard            = The display board in the restaurant showing live orders
Celery               = A separate delivery boy who handles emergencies
Redis                = The bulletin board where messages are pinned for others to read
```

---

## Step 0 — Everything is Running (Before the Push)

You have 3 terminals open:

```
Terminal 1: python manage.py runserver          → Django is listening on port 8000
Terminal 2: ngrok is running                    → Tunnel is active (https://abc123.ngrok-free.app)
Terminal 3: celery -A devpulse_backend worker   → Celery worker is waiting for tasks
```

And a browser tab is open at `http://127.0.0.1:8000/dashboard/` with the WebSocket connected.

```
┌─────────────────────────────────────────────────────────────┐
│  Browser Dashboard                                          │
│  ⚡ DevPulse Live Feed                                      │
│  🟢 Connected to Live Feed!                                │
│                                                             │
│  (empty — waiting for events...)                           │
└─────────────────────────────────────────────────────────────┘
        │
        │ WebSocket connection (stays open)
        ▼
   Django Channels (LiveFeedConsumer)
   Listening on group: "live_feed"
```

---

## Step 1 — You Push Code on GitHub

You edit a file on GitHub and click "Commit changes".

```
🧑‍💻 You → Click "Commit changes" on GitHub.com
```

GitHub thinks: *"Someone pushed code. I have a webhook registered. Let me notify them."*

GitHub builds a JSON payload and sends a POST request:

```
GitHub.com sends:
  POST https://abc123.ngrok-free.app/api/v1/webhooks/github/YOUR-UUID/
  
  Headers:
    X-GitHub-Event: push                              ← "What happened"
    X-Hub-Signature-256: sha256=a1b2c3d4e5...        ← "Proof it's really me"
    Content-Type: application/json
  
  Body:
    {
      "ref": "refs/heads/main",
      "pusher": {"name": "lucky"},
      "commits": [{"message": "Fix bug #42"}],
      ...lots more data from GitHub...
    }
```

🍕 *Pizza analogy: The customer (GitHub) places an order through the delivery app (ngrok).*

---

## Step 2 — ngrok Forwards to Your Computer

```
Internet                          Your Computer
────────────────────────────────────────────────
GitHub.com                        
    │                             
    ▼                             
https://abc123.ngrok-free.app     
    │                             
    │  (ngrok tunnel)             
    │                             
    └─────────────────────────▶  http://localhost:8000
                                  /api/v1/webhooks/github/YOUR-UUID/
```

ngrok doesn't change anything — it just forwards the exact same request to your local Django server.

🍕 *The delivery app (ngrok) passes the order to the kitchen (Django) without changing it.*

---

## Step 3 — Django URL Routing

Django receives the request and checks its URL patterns.

📁 **File**: [devpulse_backend/urls.py]
```python
path("api/v1/", include("monitor.urls")),    # → go check monitor/urls.py
```

📁 **File**: [monitor/urls.py]
```python
path("webhooks/github/<uuid:integration_id>/", GitHubWebhookView.as_view(), name="github-webhook"),
```

Django matches the URL and says:
- ✅ URL matches `webhooks/github/<uuid>/`
- ✅ Extract `integration_id` from the URL (your UUID)
- ✅ Call `GitHubWebhookView.post()`

```
URL: /api/v1/webhooks/github/abc-123-def-456/

Django: "I'll break this down..."
  /api/v1/                      → match in devpulse_backend/urls.py → go to monitor/urls.py
  webhooks/github/              → match!
  abc-123-def-456               → this is the <uuid:integration_id>
  
  → Call GitHubWebhookView.post(request, integration_id="abc-123-def-456")
```

🍕 *The kitchen reads the order slip and figures out which chef (view) should handle it.*

---

## Step 4 — Permission & Authentication Check

Before `post()` runs, DRF checks permissions.

📁 **File**: [monitor/views.py]
```python
class GitHubWebhookView(APIView):
    permission_classes = [AllowAny]       # Anyone can access
    authentication_classes = []           # Don't check for JWT token
```

```
DRF checks:
  Authentication: [] (empty) → Skip authentication entirely
  Permission: AllowAny       → Let everyone in
  
  Result: ✅ Request is allowed through
```

🍕 *The kitchen door is open to everyone — no membership card needed. (GitHub can't have a membership card because it's an external service.)*

---

## Step 5 — The View Runs: `GitHubWebhookView.post()`

Now the actual code runs, step by step:

### 5a — Find the Integration

📁 **File**: [views.py line 500]
```python
integration = Integration.objects.get(id=integration_id, is_active=True)
```

```
Database query:
  SELECT * FROM monitor_integration WHERE id='abc-123-def-456' AND is_active=True

Found:
  ┌──────────────────┬─────────────────────┬───────────┬──────────────────────────────┐
  │ id               │ name                │ platform  │ secret_token                 │
  │ abc-123-def-456  │ My Real GitHub Repo │ GITHUB    │ devpulse-github-secret-2026  │
  └──────────────────┴─────────────────────┴───────────┴──────────────────────────────┘
```

### 5b — Verify the HMAC Signature

📁 **File**: [views.py lines 502-515]
```python
signature_header = request.headers.get("X-Hub-Signature-256")
# GitHub sent: "sha256=a1b2c3d4e5..."

expected_signature = "sha256=" + hmac.new(
    key=integration.secret_token.encode("utf-8"),     # Our secret: "devpulse-github-secret-2026"
    msg=request.body,                                  # The raw JSON body
    digestmod=hashlib.sha256,
).hexdigest()
# We calculated: "sha256=a1b2c3d4e5..."

hmac.compare_digest(signature_header, expected_signature)
# "sha256=a1b2c3d4e5..." == "sha256=a1b2c3d4e5..." → ✅ Match! It's really from GitHub.
```

```
What's happening:

  GitHub knows the secret  ──┐
                              ├──▶  Both create the SAME hash  ──▶  Hashes match? ✅ Trusted!
  We also know the secret  ──┘

  An attacker doesn't know the secret  ──▶  Can't create the right hash  ──▶  ❌ Rejected!
```

🍕 *The kitchen verifies the order has the right secret stamp — not a prank call.*

### 5c — Read the GitHub Event Type

📁 **File**: [views.py line 517]
```python
github_event = request.headers.get("X-GitHub-Event", "unknown")
# github_event = "push"
```

GitHub tells us WHAT happened via this header. It's NOT in the JSON body — it's in the **header**.

### 5d — Parse GitHub's Data into Our Format

📁 **File**: [views.py lines 526, 489-500]
```python
event_type, severity, message = self.parse_github_event("push", request.data)
```

Inside `parse_github_event`:
```python
# github_event == "push", so this branch runs:
if github_event == "push":
    pusher = data.get("pusher", {}).get("name", "unknown")       # → "username"
    branch = data.get("ref", "").replace("refs/heads/", "")       # → "main"
    commits_count = len(data.get("commits", []))                  # → 1
    
    return ("CODE_PUSH", "INFO", "lucky pushed 1 commit(s) to main")
```

```
Translation:

  GitHub sends:                          We convert to:
  ┌──────────────────────────────┐       ┌────────────────────────────────────────────┐
  │ "ref": "refs/heads/main"     │  ──▶  │ event_type = "CODE_PUSH"                   │
  │ "pusher": {"name": "lucky"}  │  ──▶  │ severity   = "INFO"                        │
  │ "commits": [{...}]           │  ──▶  │ message    = "username pushed 1 commit(s)..." │
  └──────────────────────────────┘       └────────────────────────────────────────────┘
```

🍕 *The customer says "I want a Margherita with extra cheese". The kitchen translates it to: Order Type = PIZZA, Priority = NORMAL, Description = "Margherita + extra cheese".*

### 5e — Save to Database

📁 **File**: [views.py lines 529-532]
```python
payload = dict(request.data)
payload["message"] = message    # Add our parsed message to the raw data

ActivityLog.objects.create(
    integration=integration,     # → "My Real GitHub Repo"
    event_type=event_type,       # → "CODE_PUSH"
    severity=severity,           # → "INFO"
    payload=payload,             # → {all GitHub data + "message": "username pushed 1 commit(s) to main"}
)
```

```
New row in ActivityLog table:
┌──────────┬──────────────────────┬────────────┬──────────┬─────────────────────────────┐
│ id       │ integration          │ event_type │ severity │ payload                     │
│ new-uuid │ My Real GitHub Repo  │ CODE_PUSH  │ INFO     │ {..., "message": "user..." │
└──────────┴──────────────────────┴────────────┴──────────┴─────────────────────────────┘
```

### 5f — Return Response to GitHub

```python
return Response(
    {"status": "success", "message": "GitHub push event received!"},
    status=status.HTTP_202_ACCEPTED
)
```

GitHub sees `202 Accepted` → green ✅ in the webhook delivery log.

🍕 *The kitchen tells the delivery app: "Order received! We're working on it."*

---

## Step 6 — Signal Fires Automatically

**You didn't call this.** Django called it FOR you because you saved an `ActivityLog`.

📁 **File**: 
```python
@receiver(post_save, sender=ActivityLog)
def on_activity_log(sender, instance, created, **kwargs):
```

```
What triggers this:

  ActivityLog.objects.create(...)     ← You did this in the view (Step 5e)
         │
         ▼
  Django saves the row to PostgreSQL
         │
         ▼
  Django checks: "Does anyone want to know about this save?"
         │
         ▼
  Finds: @receiver(post_save, sender=ActivityLog) ← YES! This function is listening!
         │
         ▼
  Calls: on_activity_log(sender=ActivityLog, instance=<the new log>, created=True)
```

🍕 *The kitchen writes the order in the logbook. A bell AUTOMATICALLY rings because it's connected to the logbook (you don't ring it manually).*

---

## Step 7 — Signal Pushes to WebSocket

📁 **File**: [signals.py lines 14-30]
```python
channel_layer = get_channel_layer()     # Get the Redis connection

log_data = {
    "event_type": "CODE_PUSH",
    "severity": "INFO",
    "message": "username pushed 1 commit(s) to main",
    "integration": "My Real GitHub Repo",
    "timestamp": "2026-06-11T12:00:00+05:30",
}

async_to_sync(channel_layer.group_send)(
    "live_feed",           # Send to ALL browsers in this group
    {
        "type": "new_activity",     # Call the "new_activity" method on each consumer
        "data": log_data,
    },
)
```

```
What happens:

  Signal                  Redis                    Consumer (in browser's connection)
  ──────                  ─────                    ──────────
     │                       │                          │
     │  "Send this to       │                          │
     │   live_feed group"   │                          │
     │──────────────────▶   │                          │
     │                      │  "I have a message       │
     │                      │   for live_feed group"   │
     │                      │─────────────────────▶    │
     │                      │                          │
     │                      │                   new_activity() runs!
```

🍕 *The bell rings → the kitchen manager pins the order on the bulletin board (Redis) → the display board operator sees it and updates the board.*

---

## Step 8 — Consumer Sends to Browser

📁 **File**: [monitor/consumers.py line 14-15]

```python
async def new_activity(self, event):
    await self.send(text_data=json.dumps(event["data"]))
```

```
What happens:

  Consumer receives event:
    event = {
        "type": "new_activity",
        "data": {
            "event_type": "CODE_PUSH",
            "severity": "INFO", 
            "message": "lucky pushed 1 commit(s) to main",
            ...
        }
    }
  
  Consumer does:
    self.send(text_data='{"event_type":"CODE_PUSH","severity":"INFO","message":"username pushed 1 commit(s) to main",...}')
    
         │
         │  WebSocket connection (already open since page loaded)
         ▼
    Browser receives the JSON string
```

🍕 *The display board operator writes the order on the board for everyone to see.*

---

## Step 9 — Browser JavaScript Updates the Dashboard

📁 **File**: `templates/dashboard.html` (JavaScript)

```javascript
ws.onmessage = function(e) {
    var data = JSON.parse(e.data);
    // data = {event_type: "CODE_PUSH", severity: "INFO", message: "username pushed 1 commit(s)...", ...}
    
    var card = document.createElement("div");
    card.className = "event INFO";           // Blue border (INFO = blue)
    card.innerHTML = "<strong>CODE_PUSH: lucky pushed 1 commit(s) to main</strong>" +
                     "<br><small>My Real GitHub Repo — 2026-06-11T12:00:00</small>";
    
    feed.insertBefore(card, feed.firstChild);   // Add to TOP of feed
};
```

```
Dashboard BEFORE:                    Dashboard AFTER:
┌────────────────────────────┐       ┌────────────────────────────────────────────┐
│ ⚡ DevPulse Live Feed       │       │ ⚡ DevPulse Live Feed                       │
│ 🟢 Connected               │       │ 🟢 Connected                               │
│                            │       │                                            │
│ (empty)                    │  ──▶  │ ┌────────────────────────────────────────┐ │
│                            │       │ │ 🔵 CODE_PUSH: lucky pushed 1          │ │
│                            │       │ │    commit(s) to main                   │ │
│                            │       │ │ My Real GitHub Repo — 12:00:00        │ │
│                            │       │ └────────────────────────────────────────┘ │
└────────────────────────────┘       └────────────────────────────────────────────┘

No page refresh needed! ✨
```

🍕 *The customer in the restaurant sees their order appear on the display board instantly — without asking anyone!*

---

## Step 10 — (Only If CRITICAL) Celery Task Runs

This step **didn't happen** for our push event because severity was `INFO`. But if someone sent a `CRITICAL` event (like `SERVER_CRASH`), here's what would also happen:

📁 **File**: [signals.py lines 33-39]

```python
if instance.severity == "CRITICAL":                           # Only for critical events!
    SystemAlert.objects.create(activity_log=instance)          # Save alert to database
    
    send_critical_alert_notification.delay(                    # Tell Celery to handle it
        event_type=instance.event_type,
        message=instance.payload.get("message", "No details provided.")
    )
```

```
  Signal:  "This is CRITICAL! Celery, handle this!"
     │
     │  .delay() puts a task in Redis queue
     ▼
  Redis queue:  [Task: send_critical_alert_notification("SERVER_CRASH", "Server is down!")]
     │
     │  Celery worker picks it up from Terminal 3
     ▼
  Terminal 3 output:
    ============================================================
    EMERGENCY ALERT — CRITICAL EVENT DETECTED!
       Event Type : SERVER_CRASH
       Message    : Server is down!
       Action     : Emergency Email Sent!
    ============================================================
```

🍕 *If the order is marked URGENT, the kitchen also calls a separate delivery boy (Celery) to rush it. The kitchen doesn't wait for the delivery — it just makes the call and moves on to the next order.*

---

## The Complete Journey — One Picture

```
  ① GitHub: "Someone pushed code!"
       │
       ▼
  ② ngrok tunnel (public → localhost)
       │
       ▼
  ③ Django URL routing → GitHubWebhookView
       │
       ▼
  ④ Permission check (AllowAny ✅)
       │
       ▼
  ⑤ View runs:
       ├── Find Integration in database
       ├── Verify HMAC signature
       ├── Parse GitHub data → our format
       ├── Save ActivityLog to PostgreSQL
       └── Return 202 to GitHub
               │
               │ (database save triggers...)
               ▼
  ⑥ Signal fires automatically (post_save)
       │
       ├────────────────────────────────────┐
       ▼                                    ▼
  ⑦ WebSocket push                    ⑩ If CRITICAL:
       │                                    ├── Create SystemAlert
       ▼                                    └── Celery .delay()
  ⑧ Consumer sends to browser                    │
       │                                          ▼
       ▼                                    Terminal 3: 🚨 ALERT!
  ⑨ Dashboard updates instantly!
```

---


</details>
