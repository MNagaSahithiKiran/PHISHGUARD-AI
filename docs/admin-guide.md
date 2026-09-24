# PhishGuard AI — Platform Administrator Guide

## Role & Responsibilities
Administrators maintain authority over user provisioning, account activations, security audit trails, and system health diagnostics.

---

## 1. Accessing the Admin Portal
- The Admin Portal is available at `/admin` and is restricted to authenticated users with the `admin` role.
- If a standard analyst attempts to access administrative routes, the backend returns `403 Forbidden`.

---

## 2. User & Analyst Management
Navigate to **Admin Portal &rarr; User Accounts**:
- **View All Analysts**: Displays account name, email address, role badge, total scans initiated, and account creation date.
- **Deactivate / Activate Account**: Click **Deactivate** to suspend an analyst's login access. Deactivated users cannot log in or generate scans.
- **Role Promotion & Demotion**: Click **Promote to Admin** to grant administrative privileges, or **Demote to User** to return an administrator to standard analyst status.
- *Guardrail*: Administrators cannot deactivate or demote their own account to prevent system lockout.

---

## 3. Auditing Security Event Trails
Navigate to **Admin Portal &rarr; Security Audit Logs**:
- Every security event is recorded with:
  - Exact UTC timestamp
  - Event type (`USER_LOGIN`, `SCAN_INITIATED`, `REPORT_DOWNLOAD`, etc.)
  - User identity or Anonymous/System flag
  - Client IP address
  - Event outcome (`success` or `failure`)
  - Extended context payload
- **Search & Filter**: Search logs by event type or user email address to investigate anomalous access patterns.

---

## 4. Deep System Diagnostics & Health Monitoring
Navigate to **Admin Portal &rarr; Deep Diagnostics & Health**:
- **Database Query Latency**: Real-time roundtrip query latency against the persistent database.
- **Screenshot Storage**: Verifies that the local quarantined screenshot directory is readable, writable, and within size caps.
- **AI Model File Verification**:
  - `URL RandomForest`: verifies file presence and byte size.
  - `Visual MobileNetV2`: verifies PyTorch weights file presence.
  - `Fusion Stacking Meta-Classifier`: verifies Joblib model presence.
  - `Probability Calibrator`: verifies Platt calibrator presence.
- **Python Environment**: Reports active Python runtime version and dependencies.
