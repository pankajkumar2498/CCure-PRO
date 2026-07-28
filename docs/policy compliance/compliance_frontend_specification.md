# CCure Audit PRO — Compliance Engine Frontend Specification

This document specifies the page-by-page frontend architecture for the CCure Audit PRO Policy Compliance Engine. It outlines standard React component structures, local state interfaces, API call mappings, filters, and UX behaviors.

---

## 1. Routing & Layout Integration

All compliance views are grouped under a sub-router module `/compliance/*` mapped inside `App.jsx`.

### 1.1. Sidebar Modification (`AppLayout.jsx`)

The sidebar link for "Compliance" is redirected from the reports tab to the new workspace root:

```javascript
{ id: "compliance", label: "Compliance", Icon: IcoCheckCircle, route: "/compliance", permission: { resource: "compliance", action: "read" } }
```

---

## 2. Page-by-Page Specifications

### 2.1. Marketplace (`/compliance/marketplace`)

- **Components**: Grid of standards cards (`ISO 27001`, `CIS Benchmarks`, `NIST 800-53`), search inputs, installation status banners.
- **State**:
  ```typescript
  interface MarketplaceState {
    frameworks: Array<{
      id: string;
      name: string;
      is_enabled: boolean;
      controls_count: number;
    }>;
    loading: boolean;
    installingId: string | null;
  }
  ```
- **API Calls**:
  - `GET /api/compliance/marketplace` ➔ Fetch catalog frameworks.
  - `POST /api/compliance/marketplace/{id}/install` ➔ Enable framework for tenant.
- **Permissions**: Requires `compliance:manage_frameworks` scope to click "Install". Readers can view installation counts only.

### 2.2. Compliance Dashboard (`/compliance/dashboard`)

- **Components**:
  - Circular progress gauge (SoA simple score).
  - Line chart component (30/90-day score history trend).
  - 4-Quadrant grid representing ORG, PPL, PHY, and TECH themes.
  - Headline cards (Overall Compliance, Critical Controls failed, Top non-compliant assets).
- **State**:
  ```typescript
  interface DashboardState {
    kpis: {
      score_pct: number;
      weighted_score_pct: number;
      failed_critical: number;
    };
    trends: Array<{ date: string; score: number }>;
    themeScores: Record<string, number>;
  }
  ```
- **Filters**: Asset tagging, OS type (Windows/Linux/Any), and department site.
- **Sorting**: Assets sorted by compliance rating (ascending).

### 2.3. Policies (`/compliance/policies`)

- **Components**: Table of baseline policy versions, creation drawer, and policy association cards.
- **State**:
  ```typescript
  interface PolicyState {
    policies: List<PolicyVersionDTO>;
    selectedPolicy: PolicyVersionDTO | null;
    isDrawerOpen: boolean;
  }
  ```
- **API Calls**:
  - `GET /api/compliance/policies?framework_id={id}`
  - `POST /api/compliance/policies` ➔ Create v1 policy baseline.
- **Permissions**: Requires `compliance:manage_rules` to write or publish new versions.

### 2.4. Rule Builder (`/compliance/rules/new`)

- **Components**: Standard form layout, dropdown for operator selection (`equals`, `contains`, `version_gte`), JSON validator code block, target platform toggles.
- **State**: `formFields`, `validationErrors[]`, `isSaving`.
- **Validation**: Restricts input based on check type (e.g. registry paths must have target values; port states must be integers between 1 and 65535).

### 2.5. Control Explorer (`/compliance/controls`)

- **Components**: Expandable list representing framework hierarchy, scannability filter button group, status pills, details drawer.
- **State**: `expandedControls{}`, `selectedControl`, `evidenceFiles[]`, `attestationForm`.
- **Permissions**: `compliance:attest` (to submit evidence for manual controls).

### 2.6. Findings Queue & Recommendation Panel (`/compliance/findings`)

- **Components**: Paginated table of compliance findings, exception request modal, remediation drawer, bulk action toolbar.
- **State**: `selectedFindings[]`, `activeWaiverRequest`, `remediationScript`, `reverifyJobStatus`.
- **UX**: Actionable one-click "Apply Remediation" followed by "Run verification" status indicator.

### 2.7. Exception Waiver Queue (`/compliance/exceptions`)

- **Components**: Waiver requests grid, approval panel, details dialog.
- **State**:
  ```typescript
  interface WaiverState {
    requests: List<ExceptionDTO>;
    approvalStatus: "idle" | "approving" | "rejecting";
  }
  ```
- **API Calls**:
  - `PATCH /api/compliance/exceptions/{id}` ➔ Update waiver state.
- **Permissions**: Gated to `compliance:approve_exception` scope.

### 2.8. Scan Schedules (`/compliance/schedules`)

- **Components**: Active cron list, interval select components, scoped host selectors, trigger alerts config.
- **State**: `schedules[]`, `isFormOpen`, `savingStatus`.
- **Permissions**: Gated to `compliance:manage_schedules` scope.

### 2.9. Reports & SoA Export (`/compliance/reports`)

- **Components**: Form selects for framework target, format radios (PDF, Word, CSV), export execution button.
- **State**: `selectedFrameworkId`, `exportFormat`, `isDownloading`.

### 2.10. Asset Compliance Detail Tab

- **Components**: Reusable compliance scores widget integrated inside the existing `AssetDetail.jsx` dashboard. Shows asset policy checks list, status pills, and direct "View Remediation" drawer links.

---

## 3. General Frontend Design Patterns

### 3.1. Quiet Loading Pattern

To prevent UI flickering during background table refreshes or page changes, table layouts render a progress-bar indicator under headers rather than unmounting the entire DOM.

```jsx
{
  loading && <div className="loading-progress-bar" />;
}
<TableData data={findings} />;
```

### 3.2. Error Handling & Validation Failures

- **Axios Interceptor Integration**: Standard handles for HTTP status returns are wired through the central API client:
  - `401 / 403` ➔ Prompts unauthorized modal notification.
  - `422 (Validation Error)` ➔ Maps errors to specific form fields inline.
- **Fallback UI**: Individual cards or graphs use boundaries (`ErrorBoundary.jsx`) to prevent whole screen freezes if a single chart component fails to render.
