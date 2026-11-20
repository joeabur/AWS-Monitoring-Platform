# Platform capability assessment and modernization roadmap

**Assessment date:** 2026-11-20

**Evidence boundary:** repository and local CI/code paths only. No AWS account, production
deployment, monitored account, or live telemetry source was available for this review. A configured
Terraform resource or a UI label is not evidence that a corresponding AWS capability is deployed or
collecting data.

## Executive assessment

This repository is a credible **AWS security-event monitoring and incident-workflow application**:
it normalizes and deduplicates CloudTrail-shaped events, runs versioned detections, correlates alerts
into incidents, stores investigation/audit history, imports posture reports, and supports a narrowly
scoped response workflow. There is also an opt-in production Terraform environment for the
application itself.

It is **not currently a general-purpose cloud infrastructure observability platform** and cannot
yet claim customer-workload metric coverage, APM, distributed tracing, cost visibility, resource
inventory, topology, or continuous AWS service health. CloudWatch metrics emitted by application
code are platform self-telemetry (API request/latency, worker batch, and audit-export metrics); the
production CloudWatch dashboard and alarms monitor this platform's own runtime.

The highest-value modernization is to keep the security-event product boundary clear, then add a
carefully scoped infrastructure-monitoring vertical slice (inventory plus metrics with freshness
and data provenance) before expanding service coverage. Avoid representing empty or unavailable
data as a healthy zero.

### Verified strengths

- Durable event pipeline primitives: normalization, redaction of selected sensitive fields,
  idempotency, SQS partial-batch retry reporting, and DLQs.
- Detection evidence and analyst workflow: versioned rules, persisted alerts, deduplication,
  incident correlation, notes, assignment, lifecycle audit, and limited approval-gated response.
- Bounded AWS finding integration code for GuardDuty, Security Hub, and Config, plus STS account
  identity checks and region discovery.
- An opt-in, read-only MCP interface for exposing selected incident/finding context to compatible
  clients; there is no first-party LLM runtime or validated AI recommendation workflow.
- Cognito OIDC production option, role-based authorization, non-root images, protected production
  configuration, managed database credentials, opt-in Terraform, operational retention, and
  compliance-mode archive exports.
- The dashboard is based on persisted application records rather than hard-coded sample counts.

### Important limitations

- None of the production AWS infrastructure has been applied or exercised in an AWS account.
- The cross-account event module consumes events delivered to its EventBridge bus; it does not
  create source-account CloudTrail trails or cross-account bus forwarding.
- The AWS finding sync endpoints are synchronous, manually invoked APIs. The present frontend does
  not provide a complete scheduled-sync control plane.
- Customer workload inventory and CloudWatch metrics are not collected. Resource ARNs in findings
  and events are evidence, not an inventory or dependency graph.
- The dashboard is a single-page security operations view, not the multiple role-specific
  observability workspaces in the requested scope.
- Access is role-based at the application level, but users do not have per-account entitlements;
  configured monitored accounts are shared by the deployment.

## Evidence and how to read the matrix

The application boundary is described in [README.md](../README.md),
[architecture.md](architecture.md), the FastAPI routers under `backend/app/api/`, AWS calls in
[aws.py](../backend/app/integrations/aws.py), and the production resources in
[main.tf](../infrastructure/terraform/environments/production/main.tf). Detection and incident
behavior is implemented in `backend/app/detections/`, `backend/app/ingestion/`, and
`backend/app/api/incidents.py`.

Status definitions:

- **Fully implemented:** the feature is present end-to-end in application code and tests. This
  status does not mean it is deployed to AWS.
- **Partially implemented:** there is useful but bounded, manual, event-only, or deployment-only
  support; important aspects of the requested capability are absent.
- **Implemented, needs improvement:** the core feature works, but its operational completeness,
  scale, coverage, or user experience is not enterprise-grade.
- **Not implemented:** no working product path was found in the repository.

## AWS service coverage

“Customer telemetry” below means telemetry from configured monitored AWS accounts. Platform
infrastructure telemetry is called out separately. Unless otherwise stated, customer resource
history, metric-based alarms, and resource drill-down are not available.

| AWS service / capability | Status | Verified current behavior | Material gap |
|---|---|---|---|
| EC2 | Partially implemented | CloudTrail activity and selected exposure changes can produce detections; EC2 resource ARNs may appear as event evidence. | No EC2 inventory, instance state/health, CPU, network, disk, memory, trends, or resource detail view. |
| ECS | Partially implemented | The optional production stack runs this platform's API and frontend on Fargate and configures CPU autoscaling. | No inventory or metrics for customer ECS clusters/services/tasks. Platform task logs and service health are not customer workload monitoring. |
| EKS | Not implemented | No EKS API, Kubernetes integration, or agent/collector configuration found. | No cluster, node, pod, workload, or control-plane telemetry. |
| Lambda | Partially implemented | A Lambda function consumes this platform's SQS event queue; Terraform configures its timeout and execution role. | No customer Lambda inventory, invocation/error/throttle/duration metrics, logs, traces, or resource drill-down. |
| RDS / Aurora | Partially implemented | The production environment creates its own private RDS PostgreSQL instance and alarms on platform DB CPU and free storage. | No customer database inventory/metrics, Performance Insights/Database Insights, connection trends, slow-query visibility, or Aurora coverage. |
| DynamoDB | Not implemented | No DynamoDB collector or metrics query found. | No table inventory, capacity, throttling, latency, or cost view. |
| S3 | Partially implemented | CloudTrail detections include selected S3 policy/ACL/public-access changes; the platform creates an Object Lock archive bucket for its audit exports. | No monitored-bucket inventory, request/storage metrics, access-logging health, lifecycle analysis, or complete configuration posture. |
| VPC, NAT, networking | Partially implemented | CloudTrail detections cover selected security-group exposure changes; the platform stack has VPC/NAT resources. | No VPC Flow Logs integration, packet/flow analytics, NAT bytes/connection metrics, reachability analysis, or network map. |
| Elastic Load Balancing | Partially implemented | The production stack creates an ALB for this platform. | No customer load-balancer inventory, target health, request/error/latency metrics, or drill-down. |
| Auto Scaling Groups | Not implemented | CPU autoscaling is configured for the platform's ECS services only. | No customer ASG inventory, scaling activity, capacity history, or predictive capacity signals. |
| API Gateway | Not implemented | No API Gateway collector or metrics path found. | No API request, latency, throttling, integration error, or stage-level coverage. |
| CloudFront | Not implemented | No CloudFront collector or distribution metrics path found. | No distribution inventory, cache/error/latency metrics, origin health, or edge drill-down. |
| Route 53 | Partially implemented | Optional Route 53 alias records can be created for the platform's ALB. | No monitored hosted-zone/record inventory, health-check status, query metrics, or DNS drill-down. |
| SQS / SNS | Partially implemented | The production platform has an encrypted SQS event queue and DLQs with CloudWatch queue alarms/dashboard. SNS can notify operators about platform alarms. | No customer queue/topic inventory, backlog/age history, delivery metrics, or alerting. |
| CloudWatch | Partially implemented | API and worker emit Embedded Metric Format self-telemetry; production Terraform declares CloudWatch log groups, dashboard, and alarms for the platform. | No customer-account `GetMetricData`/logs/alarms ingestion, metric explorer, resource dashboards, or configurable metric alarms. |
| CloudTrail | Partially implemented | Selected-account management-event routing is declared in an opt-in EventBridge/SQS module; event normalization, detection, search, and history exist. | No source trail creation/validation, data-event coverage, cross-account forwarding, delivery completeness SLO, or production freshness evidence. |
| AWS Config | Partially implemented | Config compliance changes can enter EventBridge; a bounded API can sync rule evaluations. | Not a continuous full compliance inventory; no managed rule coverage validation, recorder/delivery health SLO, or historical compliance dashboard. |
| AWS Cost Explorer / Budgets | Not implemented | No Cost Explorer, Budgets, CUR/Data Export, or cost anomaly API calls found. | No spend, forecasting, cost allocation, budget alert, or rightsizing view. |
| Security Hub | Partially implemented | Findings can be routed as events or fetched with a bounded `GetFindings` API, normalized, stored, and alerted. | No scheduled ingestion guarantee, organization aggregation/configuration coverage view, finding-closure synchronization, or comprehensive compliance posture. |
| GuardDuty | Partially implemented | Findings can be routed as events or fetched with bounded `ListFindings`/`GetFindings` calls and stored. | No detector/plan coverage dashboard, scheduled sync SLA, suppression workflow, or complete threat-investigation context. |
| Trusted Advisor | Not implemented | No Trusted Advisor API integration found. | No service-limit, fault-tolerance, operational, security, or cost recommendation ingestion. |
| Inspector | Not implemented | No Inspector API/event integration found. | No software-vulnerability finding inventory, resource correlation, trend, or alerting. |
| IAM Access Analyzer | Not implemented | No Access Analyzer integration found. | No external-access findings, unused access analysis, or IAM exposure dashboard. |
| Audit archive | Implemented, needs improvement | Application incident and response audit rows are exported to a versioned S3 Object Lock bucket with COMPLIANCE retention in the optional stack. | No live deployment, archive restore drill, cross-account backup, or independent end-to-end archive verification. Raw event evidence is separately deleted under its configured retention policy. |

### Data timeliness, drill-down, history, alerts, recommendations

| Area | Verified behavior | Assessment |
|---|---|---|
| Real-time | EventBridge/SQS can deliver selected events after source trails and forwarding are configured. | Event path is deployment-gated; there is no end-to-end freshness/coverage SLO or demonstrated AWS latency. |
| Delayed/manual | GuardDuty, Security Hub, and Config have API sync paths; callers set a bounded per-call limit. | Sync is request/response, not a scheduled ingestion service; UI does not offer a complete sync console. |
| Historical trends | Database stores normalized event/finding/alert/incident history; dashboard supports time windows over persisted records. | These are security records, not metric time series. Raw events are pruned; finding, alert, and audit retention differ. |
| Drill-down | Event and incident APIs expose related evidence, timeline, notes, findings, and audit history. | Drill-down is incident/evidence-centric; there is no customer resource inventory or resource metric page. |
| Alerts | Static versioned rules, thresholds for selected event patterns, deduplication, incident correlation, and outbound delivery retry exist. | No end-user-configurable threshold editor, metric rules, anomaly detection, maintenance windows, or escalation policy. |
| Recommendations | Rules include human-authored investigation steps and response recommendations; imported audit findings retain remediation. | Recommendations are not generated from comprehensive telemetry; no quantified cost/savings or verified impact analysis. |

## Competitive benchmark

The comparison is based on publicly documented product capabilities, not a hands-on trial or
pricing comparison. Major vendors offer broad telemetry collection and correlation; the platform
should compete through a narrower, evidence-first AWS security/workflow focus rather than attempt
to recreate every proprietary suite feature.

| Benchmark | Publicly documented strengths relevant here | Relative position and practical differentiation |
|---|---|---|
| Datadog | Infrastructure/APM, end-to-end traces correlated with logs/metrics, metric monitors, maintenance downtimes, and notification guidance ([APM](https://docs.datadoghq.com/tracing/), [monitors](https://docs.datadoghq.com/monitors/)). | This platform has a focused AWS security-event evidence and approval-audited response workflow, but lacks broad metrics, APM, trace correlation, and dynamic monitor operations. |
| Dynatrace | Distributed tracing, service-level views, profiling, logs, metrics, and digital experience in one application-observability surface ([docs](https://docs.dynatrace.com/docs/observe/application-observability)). | Current app handles security events/incidents but has no service graph, trace, profile, or frontend telemetry. Compete on transparent evidence and least-privilege AWS workflows, not autonomous root-cause claims. |
| New Relic | APM, infrastructure, dashboards, alerting, browser monitoring, integrations, and error investigation ([platform overview](https://docs.newrelic.com/docs/new-relic-solutions/get-started/intro-new-relic/)). | The current product has incident work queues and AWS finding context, but no broad application/infrastructure telemetry or customizable dashboards. |
| Grafana | Application observability workflows, OpenTelemetry/Prometheus models, frontend observability, and knowledge-graph based correlation ([application monitoring](https://grafana.com/docs/grafana-cloud/observe-and-act/monitor-applications/)). | Open standards and composable dashboarding are strong options for this platform; current UI is a single fixed SOC view without a telemetry backend/query model. |
| Amazon CloudWatch | Native AWS metrics/logs/alarms/dashboards, cross-account observability, OpenTelemetry, Application Signals, Synthetics, and SLOs ([overview](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)). | Best near-term backend for AWS-native infrastructure metrics. The repository currently monitors its own runtime with CloudWatch, not customer-account resources. |
| LogicMonitor | Enterprise infrastructure observability and broad hybrid/cloud monitoring ([platform](https://www.logicmonitor.com/platform)). | The current platform has no comparable inventory or dependency graph and should not claim fleet-monitoring parity. |
| Splunk Observability Cloud | Publicly describes APM, infrastructure, database, digital-experience, logs, synthetic monitoring, and AI-assisted troubleshooting ([overview](https://www.splunk.com/en_us/products/observability-cloud.html)). | The current platform's incident/security evidence is narrower and should integrate with existing observability/SIEM platforms rather than duplicate their data platforms. |

## Product and interface assessment

- One authenticated Next.js page currently contains overview filters, counters, severity/rule summaries,
  incident queue, integration health, imported audit findings, and incident investigation.
- Time range, account, region, and severity filters exist on the security dashboard. Incident and
  event details have evidence drill-down. Loading, error, and empty states are present.
- The navigation is anchor-based and primarily labels sections in the same page. Dedicated
  Infrastructure, Performance, Cost, Security Posture, Resource Inventory, and executive views are
  absent.
- The integration panel previously ignored selected account/region and the top-level AWS connection
  indicator conflated a failing service sync with account credential access. This pass scopes the
  panel to selected filters and bases the connection indicator on recent STS health; service-sync
  outcomes remain visible separately.
- Accessibility, keyboard behavior, mobile layouts, and usability with production data volume require
  human/browser testing; source inspection alone cannot establish those outcomes.

## Architecture, reliability, and security findings

### Reliability and scale

1. Finding sync performs AWS API calls inside synchronous FastAPI requests. Although SDK retries,
   timeouts, pagination, account verification, and response caps exist, slow or throttled accounts
   consume request capacity. Move sync to a durable scheduled/job queue and expose run status,
   checkpoints, retry state, and freshness.
2. Event ingestion evaluates context by querying up to 1,000 account events for each new event.
   This is practical for the current scale but becomes database work proportional to event rate;
   load/soak tests and query-plan evidence are missing.
3. There is no customer CloudWatch metric ingestion/aggregation, retention tiering for time series,
   or configurable cardinality budget. Querying every metric/resource at short intervals could be
   expensive and should not be the default.
4. Dashboard counters read persisted records. `aws_connection_status` is not proof of end-to-end
   collection; it represents the freshness of configured-account STS checks. Service integrations
   need their own freshness and expected-coverage indicators.
5. Scheduled retention/export tasks exist in Terraform, but task failure notification depends on
   optional email configuration. No AWS schedule, database, queue, archive, or recovery has been
   validated in a deployed environment.
6. The optional MCP surface is a safe, read-only context interface, not an AI assistant. There is no
   configured model, evidence citation/evaluation system, or LLM-generated root-cause analysis.

### Security and governance

- **Good controls:** Cognito access-token verification, database-authoritative roles, account-ID
  verification after STS assumption, configured role ARNs, separate response role, non-root
  containers, TLS database connections, Secrets Manager credentials, encrypted SQS/RDS/S3, public
  archive access blocked, and no secret-bearing configuration in the browser bundle.
- **Scope gap:** application roles do not carry account-level entitlements; all authorized users see
  the configured account population. Do not treat this as tenant isolation for a shared SaaS model.
- **Credential privilege:** the current ECS API/worker roles can read the RDS master secret. Replace
  this with a dedicated application DB principal and restrict migration/administrative credentials
  to the migration task.
- **Network controls:** the optional stack has private application subnets but broad task egress
  through NAT, no VPC endpoints, no WAF, and no VPC Flow Logs. Review network egress, ingress
  throttling, and security-group ownership before deployment.
- **Least privilege:** cross-account role ARNs are configurable, but their trust policies and
  permissions are external operator responsibilities. The CI path validates Terraform syntax, not
  effective IAM access or AWS policy simulation.
- **Retention:** raw CloudTrail event rows and alert references are removed after the configured
  cutoff. Incident/response audit rows remain in PostgreSQL; exported archive objects are retained
  under Object Lock. Validate this split against legal holds, privacy deletion, and incident
  evidence requirements.
- **Supply chain/recovery:** image signatures/provenance, production release workflow, restore
  exercises, archive verification, live cloud security testing, and independent assessment remain
  deployment gates.

### Permissions to plan for

Current code paths use `sts:GetCallerIdentity`, `sts:AssumeRole`, `ec2:DescribeRegions`,
`guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings`,
`securityhub:GetFindings`, `config:DescribeComplianceByConfigRule`, and
`config:GetComplianceDetailsByConfigRule`. The production worker also needs scoped SQS receive/delete
and RDS secret access; the archive task needs the RDS secret and `s3:PutObject` /
`s3:PutObjectRetention` only under the archive prefix. Review actual role policies before adding any
new integration.

Future permissions should be isolated by collector and service:

- Inventory and standard metrics: service-specific `Describe*`/`List*` reads and
  `cloudwatch:GetMetricData`/`cloudwatch:ListMetrics`; use STS AssumeRole into explicit accounts.
- Cost: `ce:GetCostAndUsage`, `ce:GetCostForecast`, `ce:GetAnomalies`, and read-only Budgets actions
  such as `budgets:ViewBudget`; Cost Explorer must be enabled and its data is delayed.
- Inspector / Access Analyzer / Trusted Advisor: only their specific read APIs and only if operators
  enable the integration. Do not grant wildcard write or remediation actions to collectors.
- OpenTelemetry: use an ADOT Collector or OTLP receiver and scoped CloudWatch/X-Ray export permissions
  if AWS backends are selected. Sampling, redaction, and retention must be configured.

## Prioritized implementation roadmap

Effort is relative (`S` small, `M` medium, `L` large, `XL` program). Each item requires acceptance
tests and explicit opt-in for paid or high-volume AWS collection.

| Priority / capability | Business value and success measure | Technical requirements | AWS services / permissions |
|---|---|---|---|
| **P1 — Deployment verification and release gates (M)** | Make the declared stack trustworthy; demonstrate repeatable plan, migration, smoke test, rollback, restore, and alarm delivery in a non-production AWS account. | Workload identity for CI/CD; immutable image digests/signatures; staged migration; integration tests; load and restore drills; budget cap and teardown runbook. | ECS, RDS, ECR, CloudWatch, EventBridge/SQS; narrowly scoped OIDC deployment role, no static keys. |
| **P1 — Collection freshness and completeness (M)** | Detect silent collection gaps; display last successful sync, expected source coverage, lag, and failure reason per account/service/region. Target: alert on lag and stale/incomplete collectors. | Scheduled jobs with durable checkpoints, idempotency, jitter, backoff, per-provider cursors, DLQs, run history, health API and alarm thresholds. | EventBridge Scheduler, SQS, CloudWatch; existing STS, GuardDuty, Security Hub, Config read permissions. Source-account CloudTrail/trail delivery and bus forwarding require separate reviewed setup. |
| **P1 — AWS service inventory and metric vertical slice (L)** | Give operators resource-level health instead of event-only evidence. Start with EC2, ECS, and RDS; target drill-down by account/region/resource and 1h/24h/7d trends. | Paginated inventory snapshots, stable resource IDs, tag/account/region filters, batched `GetMetricData`, metric freshness, missing-data semantics, retention/downsampling, API quotas and caching. Add memory/disk only via agent/Container Insights where those metrics are not native. | STS AssumeRole, EC2/ECS/RDS read-only `Describe*`, CloudWatch `GetMetricData`/`ListMetrics`; CloudWatch Agent or Container Insights only with explicit rollout/cost approval. |
| **P1 — Platform SLO and telemetry (M)** | Prove this monitoring platform is healthy and can detect its own outages. Define ingestion lag, API availability/latency, failed sync, DLQ age, and notification SLOs. | OpenTelemetry SDK/ADOT collector, trace/context propagation, histogram metrics, RED/USE dashboards, low-cardinality labels, error-budget alerts and tested synthetic checks. Preserve PII/secret redaction. | CloudWatch Application Signals/X-Ray or an OTLP-compatible backend, CloudWatch Synthetics optional; scoped write/export permissions. |
| **P1 — IAM and account governance hardening (M)** | Prevent privilege bleed and accidental data exposure. Success: no master DB secret in API/worker roles; tested per-account access boundaries; least-privilege review evidence. | Dedicated DB user/migration identity, account entitlements if multi-tenant, account-level audit trail, Terraform IAM simulation, ingress rate limiting, egress policy and credential-rotation tests. | Secrets Manager, IAM Identity Center/Cognito, STS, RDS; policy-specific reads only. WAF and VPC endpoints are optional cost/security decisions. |
| **P2 — Metric alerts and maintenance controls (L)** | Reduce missed performance incidents and noisy pages. Success: configurable multi-window alert rules, maintenance mute, dedup, routing, escalation/acknowledgement audit. | Persisted versioned rule definitions, safe preview/test, state machine, evaluation worker, no-data handling, notification policies, schedule/time-zone support, alert quality metrics. Start with static thresholds; add anomaly detection only after sufficient baseline. | CloudWatch metric streams or scheduled `GetMetricData`; SNS/Chatbot or existing Slack/Teams/email channels; read metrics plus SNS publish. |
| **P2 — FinOps (L)** | Explain spend changes and surface safe savings. Success: account/service/region trends, budget threshold, forecast, explainable anomaly and evidence-backed recommendation. | Daily cost cache, payer/member-account model, cost allocation tags, time-series comparison, forecast confidence, savings evidence, impact/currency disclaimers and user approvals. Do not derive resource cost where CUR cannot support it. | Cost Explorer, AWS Budgets, Cost Anomaly Detection; `ce:GetCostAndUsage`, forecast/anomaly read, `budgets:ViewBudget`. Cost Explorer API calls are metered and data is delayed; assess CUR/Data Exports for scale. |
| **P2 — Dedicated product workspaces and resource drill-down (M)** | Make the platform actionable for distinct operators without overloading the SOC screen. Success: clear executive, infrastructure, security, cost, incident views with shared filters and accessible empty/error states. | Route-based information architecture, URL-persisted filters, accessible charts/tables, role visibility, export formats, controlled auto-refresh, pagination and server-side aggregation. | No additional AWS permission by itself; consumes collected metric/finding/cost APIs. |
| **P2 — Security posture expansion (M/L)** | Broaden security context beyond event detections. Success: coverage status and deduped prioritized findings from enabled native services, with resource and finding-history drill-down. | Event plus scheduled provider reconciliation, finding workflow sync, pagination, account/region boundaries, coverage checks and exact source provenance. Integrate with native findings rather than recreate their scanners. | Security Hub, GuardDuty, Config, Inspector, IAM Access Analyzer; specific read-only `Get/List/Describe` actions. |
| **P3 — OpenTelemetry APM and traces (L/XL)** | Correlate API errors and latency to service/dependency traces. Success: sampled end-to-end traces with trace-to-incident pivot and service-level RED metrics. | Instrument API/worker/frontend, W3C trace context, OTLP pipeline, tail/head sampling, secret/PII scrubbing, trace storage and retention controls. | ADOT/OpenTelemetry, X-Ray or managed OTLP backend; service-scoped export permissions and explicit ingest-cost budgets. |
| **P3 — Grounded AI investigation assistant (L)** | Shorten investigation time without inventing evidence. Success: answers link to exact findings/events/metrics and label facts vs hypotheses; evaluations reject unsupported claims. | Retrieval only from authorized persisted records; deterministic query tools; evidence citations, account-level access checks, prompt injection defenses, redaction, audit logs, evaluation set, human approval; no arbitrary commands or direct write tools. | Optional Bedrock model/runtime and logging services; narrowly scoped invoke permission. Avoid sending unapproved sensitive evidence to third parties. |
| **P3 — Topology, change impact, and predictive insights (XL)** | Show dependencies and likely blast radius; predict capacity issues only with reliable history. Success: provenance-bearing graph edges, change/event timeline, validated prediction precision. | Resource inventory graph, AWS Config relationships/resource maps, deployment/change events, graph storage, confidence/age per edge, workload baselines, false-positive review. | AWS Config, CloudTrail, service `Describe*`, optional Neptune only if graph scale justifies cost; read-only collection roles. |
| **P3 — Guarded remediation (M/L, after P1/P2)** | Reduce time to contain known high-confidence scenarios. Success: dry-run preview, dual approval, scoped target allowlist, idempotency, rollback and complete immutable audit. | Extend existing response workflow only for well-understood playbooks; separate proposer/executor roles, approvals, blast-radius limit, maintenance window, kill switch, simulation and incident linkage. | Separate IAM role and minimal service actions (never collector role); CloudTrail audit, SNS approval channel. Remains disabled until tabletop and rollback exercises pass. |

## Recommended sequencing

1. Complete P1 deployment acceptance and account/region freshness before presenting a green
   production-coverage status.
2. Build one read-only inventory/metric slice (EC2, ECS, RDS) with explicit cost and missing-data
   semantics; validate data quality and quotas in a test account.
3. Add configurable metric alerting and dedicated infrastructure/security workspaces from the same
   API contracts.
4. Add Cost Explorer integration and expanded native security sources as separately opt-in modules.
5. Instrument with OpenTelemetry and only then add grounded AI, topology, prediction, and any further
   remediation.

Do not claim parity with Datadog, Dynatrace, New Relic, Grafana, CloudWatch, LogicMonitor, or Splunk
until the relevant telemetry, retention, alerting, multi-account scale, and operational SLOs are
measured in a deployed environment.

## Validation performed

- Backend: Ruff check/format and 100 pytest cases passed; Alembic upgraded a clean SQLite database
  through revision `0011_audit_entry_archive_markers`.
- Frontend: TypeScript check and production build passed.
- Supply chain: `npm audit --audit-level=high` and `pip-audit -r requirements.txt` found no known
  vulnerabilities in the current lock/requirements inputs.
- Local deployment: Docker Compose configuration validation passed.
- Terraform production environment and event-pipeline module: format/schema validation passed in
  this workstream. No Terraform apply, AWS API call, live account integration, or production
  performance/security test was performed.

## Benchmark references

- [Datadog APM](https://docs.datadoghq.com/tracing/) and [monitors](https://docs.datadoghq.com/monitors/)
- [Dynatrace application observability](https://docs.dynatrace.com/docs/observe/application-observability)
- [New Relic platform overview](https://docs.newrelic.com/docs/new-relic-solutions/get-started/intro-new-relic/)
- [Grafana Cloud application monitoring](https://grafana.com/docs/grafana-cloud/observe-and-act/monitor-applications/)
- [Amazon CloudWatch overview](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)
- [AWS Cost Explorer](https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html)
- [LogicMonitor platform](https://www.logicmonitor.com/platform)
- [Splunk Observability Cloud](https://www.splunk.com/en_us/products/observability-cloud.html)
