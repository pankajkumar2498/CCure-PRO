"""
Module: core.nist_csf_catalogue
Purpose: The NIST Cybersecurity Framework 2.0 Core, as data — six Functions,
         twenty-two Categories and 106 Subcategories, with NIST's own outcome
         statements, a written objective, an audit evidence checklist and an
         ISO/IEC 27001:2022 crosswalk for each.

This is the single source of truth for the CSF 2.0 catalogue.
`enrich_nist_csf_v2_seed.py` renders it into
`nist_csf_v2_controls_seed.json`; `core/nist_csf.py` re-exports the ordering
tables for the API and the report generators. Edit here, never in the JSON.

Ordering
────────
`FUNCTION_ORDER` and `CATEGORY_ORDER` are in NIST's published order — GV, ID,
PR, DE, RS, RC, and within Govern OC, RM, RR, PO, OV, SC. That order is
normative and is not alphabetical, which is what a naive `ORDER BY theme,
control_number` produced: a NIST CSF report opened on Detect and a Govern
section that ran OC, OV, PO, RM, RR, SC.

Outcome statements are NIST's own. CSF 2.0 (NIST.CSWP.29) is a work of the
U.S. Government and is not subject to copyright. Descriptions and evidence
checklists are written here: they say what the outcome is *for* and what an
assessor should expect to be shown, because 79 of the 106 Subcategories can
only be satisfied by human attestation and those two fields are the entire
prompt the reviewer works from.
"""

FUNCTION_ORDER: tuple[str, ...] = ("GV", "ID", "PR", "DE", "RS", "RC")

FUNCTION_NAMES: dict[str, str] = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

# Category code -> (Function, display name), in published order.
CATEGORY_ORDER: dict[str, tuple[str, str]] = {
    "GV.OC": ("GV", "Organizational Context"),
    "GV.RM": ("GV", "Risk Management Strategy"),
    "GV.RR": ("GV", "Roles, Responsibilities, and Authorities"),
    "GV.PO": ("GV", "Policy"),
    "GV.OV": ("GV", "Oversight"),
    "GV.SC": ("GV", "Cybersecurity Supply Chain Risk Management"),
    "ID.AM": ("ID", "Asset Management"),
    "ID.RA": ("ID", "Risk Assessment"),
    "ID.IM": ("ID", "Improvement"),
    "PR.AA": ("PR", "Identity Management, Authentication, and Access Control"),
    "PR.AT": ("PR", "Awareness and Training"),
    "PR.DS": ("PR", "Data Security"),
    "PR.PS": ("PR", "Platform Security"),
    "PR.IR": ("PR", "Technology Infrastructure Resilience"),
    "DE.CM": ("DE", "Continuous Monitoring"),
    "DE.AE": ("DE", "Adverse Event Analysis"),
    "RS.MA": ("RS", "Incident Management"),
    "RS.AN": ("RS", "Incident Analysis"),
    "RS.CO": ("RS", "Incident Response Reporting and Communication"),
    "RS.MI": ("RS", "Incident Mitigation"),
    "RC.RP": ("RC", "Incident Recovery Plan Execution"),
    "RC.CO": ("RC", "Incident Recovery Communication"),
}

# ISO/IEC 27001:2022 Annex A controls that carry a seeded rule reading an
# evidence key an adapter actually emits, and the module that produces it.
#
# `scannability` is *derived* from this set rather than asserted per
# Subcategory: a Subcategory is `auto` exactly when its crosswalk reaches one
# of these, and `manual` otherwise. Twelve Subcategories previously claimed
# `auto` against modules that do not exist (`sast_dast_scan`,
# `ha_failover_check`, `app_locker_scan`, `ir_triage_matrix`, …), and five
# more claimed `manual` while inheriting automated rules through a crosswalk
# that had no business carrying them — ID.AM-07, "inventories of data are
# maintained", was being answered by A.8.8's critical-vulnerability count.
# Deriving both fields from one table makes that class of drift impossible.
AUTOMATED_ISO_CONTROLS: dict[str, str] = {
    "A.5.18": "Offline Configuration Scan (access review)",
    "A.8.1": "Offline Configuration Scan (disk encryption, UAC)",
    "A.8.2": "Credential Validation (privileged access, MFA)",
    "A.8.5": "Credential Validation (password policy)",
    "A.8.7": "Malware Scan",
    "A.8.8": "Vulnerability Audit",
    "A.8.9": "Offline Configuration Scan (hardening baseline)",
    "A.8.13": "Offline Configuration Scan (backup frequency)",
    "A.8.15": "Offline Configuration Scan (audit policy, log retention)",
    "A.8.16": "Offline Configuration Scan (IDS/EDR presence)",
    "A.8.17": "Offline Configuration Scan (NTP)",
    "A.8.18": "Offline Configuration Scan (privilege elevation)",
    "A.8.20": "Services & Ports / Offline Configuration Scan",
    "A.8.21": "Services & Ports",
    "A.8.24": "TLS / Certificates",
}


# ─────────────────────────────────────────────────────────────────────────────
# The 106 Subcategories.
#
# `title`       NIST's outcome statement.
# `description` What the outcome is for, for the reviewer on screen.
# `checklist`   What an assessor should expect to be shown.
# `crosswalk`   ISO/IEC 27001:2022 Annex A controls, bare "A.x" form, which is
#               what /compliance/gap-analysis and the rule mapper parse.
# ─────────────────────────────────────────────────────────────────────────────

SUBCATEGORIES: dict[str, dict] = {
    # ═══ GOVERN ▸ Organizational Context ═════════════════════════════════════
    "GV.OC-01": {
        "title": "The organizational mission is understood and informs cybersecurity risk management",
        "description": "The organisation's mission and objectives are stated plainly enough that cybersecurity decisions can be traced back to them, so risk is judged by its effect on what the organisation exists to do rather than in the abstract.",
        "checklist": [
            "Published mission or strategy statement currently in force",
            "Record linking cybersecurity objectives to specific mission outcomes",
            "Evidence the link is revisited when the mission or strategy changes",
        ],
        "crosswalk": ["A.5.1"],
    },
    "GV.OC-02": {
        "title": "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered",
        "description": "The parties with a stake in the organisation's cybersecurity are identified along with what each expects, so requirements are gathered deliberately rather than arriving as complaints or audit findings.",
        "checklist": [
            "Stakeholder register naming internal and external parties",
            "Recorded cybersecurity expectations per stakeholder group",
            "Evidence those expectations were considered in a risk or planning decision",
        ],
        "crosswalk": ["A.5.5", "A.5.19"],
    },
    "GV.OC-03": {
        "title": "Legal, regulatory, and contractual requirements regarding cybersecurity, including privacy and civil liberties obligations, are understood and managed",
        "description": "Every statutory, regulatory and contractual cybersecurity obligation the organisation is subject to is identified, owned and tracked, privacy obligations included, so compliance is a managed position rather than an assumption.",
        "checklist": [
            "Register of applicable laws, regulations and contractual security clauses",
            "Named owner and current status against each obligation",
            "Record of the most recent legal or regulatory review",
        ],
        "crosswalk": ["A.5.31", "A.5.32", "A.5.34", "A.5.36"],
    },
    "GV.OC-04": {
        "title": "Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated",
        "description": "The services others rely on the organisation to deliver are identified and their criticality agreed, so protection and recovery effort is spent where an outage would be felt outside the organisation.",
        "checklist": [
            "Business impact analysis identifying externally depended-upon services",
            "Agreed criticality or service tiering",
            "Evidence the criticality decisions were communicated to service owners",
        ],
        "crosswalk": ["A.5.30"],
    },
    "GV.OC-05": {
        "title": "Outcomes, capabilities, and services that the organization depends on are understood and communicated",
        "description": "The external services, suppliers and infrastructure the organisation itself depends on are identified and the effect of their loss understood, so inherited risk is visible before an outage discovers it.",
        "checklist": [
            "Dependency map covering suppliers, platforms and utilities",
            "Impact assessment for loss of each critical dependency",
            "Evidence dependencies are reviewed on a defined cycle",
        ],
        "crosswalk": ["A.5.19", "A.5.30"],
    },
    # ═══ GOVERN ▸ Risk Management Strategy ═══════════════════════════════════
    "GV.RM-01": {
        "title": "Risk management objectives are established and agreed to by organizational stakeholders",
        "description": "What the cybersecurity risk programme is trying to achieve is written down and agreed by the people accountable for it, so later disagreements about priority have a documented reference.",
        "checklist": [
            "Documented cybersecurity risk management objectives",
            "Record of stakeholder agreement or approval",
            "Evidence objectives are reviewed at planned intervals",
        ],
        "crosswalk": ["A.5.1", "A.5.4"],
    },
    "GV.RM-02": {
        "title": "Risk appetite and risk tolerance statements are established, communicated, and maintained",
        "description": "The amount of cybersecurity risk the organisation will accept is stated in terms specific enough to decide a real case, and kept current, so acceptance decisions are consistent between teams.",
        "checklist": [
            "Approved risk appetite and risk tolerance statements",
            "Evidence of communication to risk owners and decision makers",
            "Record of the most recent review or revision",
        ],
        "crosswalk": ["A.5.1", "A.5.4"],
    },
    "GV.RM-03": {
        "title": "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes",
        "description": "Cybersecurity risk sits in the same register, on the same scale and reported through the same route as the organisation's other risks, so it can be compared and traded off against them.",
        "checklist": [
            "Enterprise risk register showing cybersecurity entries",
            "Evidence cyber risks use the enterprise scoring scale",
            "Board or executive risk report containing cybersecurity items",
        ],
        "crosswalk": ["A.5.4"],
    },
    "GV.RM-04": {
        "title": "Strategic direction that describes appropriate risk response options is established and communicated",
        "description": "The organisation states which responses (accept, mitigate, transfer, avoid) are appropriate in which circumstances, so risk owners are not each inventing a policy at the point of decision.",
        "checklist": [
            "Documented risk response strategy and decision criteria",
            "Evidence of communication to risk owners",
            "Examples of response decisions recorded against the criteria",
        ],
        "crosswalk": ["A.5.1", "A.5.4"],
    },
    "GV.RM-05": {
        "title": "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties",
        "description": "Named routes exist for raising and escalating cybersecurity risk, including risk originating with suppliers, so a concern reaches a decision maker without depending on who happens to know whom.",
        "checklist": [
            "Documented escalation and reporting paths with named roles",
            "Evidence third-party risk uses the same routes",
            "Examples of risks escalated through the documented path",
        ],
        "crosswalk": ["A.5.4", "A.5.19"],
    },
    "GV.RM-06": {
        "title": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated",
        "description": "One risk method is used across the organisation, so two teams assessing comparable exposures arrive at comparable scores and the register can be ranked meaningfully.",
        "checklist": [
            "Documented risk assessment methodology with scoring scales",
            "Evidence the method is applied in current risk assessments",
            "Record of training or communication of the method",
        ],
        "crosswalk": ["A.5.4"],
    },
    "GV.RM-07": {
        "title": "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions",
        "description": "Opportunities a security investment would open up - new markets, new assurance claims, retired legacy cost - are recorded alongside threats, so risk discussion is not only about loss avoidance.",
        "checklist": [
            "Register or minutes recording cybersecurity opportunities",
            "Evidence opportunities are assessed with the same method as threats",
            "Example of an opportunity carried into a planning or budget decision",
        ],
        "crosswalk": ["A.5.4"],
    },
    # ═══ GOVERN ▸ Roles, Responsibilities, and Authorities ═══════════════════
    "GV.RR-01": {
        "title": "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving",
        "description": "Accountability for cybersecurity risk sits with named leaders rather than with the security function alone, and their conduct visibly supports the behaviour the policy asks of everyone else.",
        "checklist": [
            "Terms of reference or charter assigning leadership accountability",
            "Minutes showing leadership review of cybersecurity risk",
            "Evidence of leadership communication on security culture",
        ],
        "crosswalk": ["A.5.2", "A.5.4"],
    },
    "GV.RR-02": {
        "title": "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced",
        "description": "Every cybersecurity duty has a named holder with the authority to discharge it, conflicting duties are separated, and the assignment is known to the people it binds.",
        "checklist": [
            "RACI or equivalent covering cybersecurity duties",
            "Evidence of segregation between conflicting duties",
            "Evidence role holders were informed and acknowledged the assignment",
        ],
        "crosswalk": ["A.5.2", "A.5.3"],
    },
    "GV.RR-03": {
        "title": "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies",
        "description": "Budget, headcount and tooling are allocated in proportion to the risk strategy the organisation has adopted, so policy commitments are funded rather than aspirational.",
        "checklist": [
            "Approved cybersecurity budget and staffing plan",
            "Evidence resourcing was justified against the risk strategy",
            "Record of resource gaps raised and their disposition",
        ],
        "crosswalk": ["A.5.2", "A.5.4"],
    },
    "GV.RR-04": {
        "title": "Cybersecurity is included in human resources practices",
        "description": "Screening, terms of employment, awareness, disciplinary process and offboarding all carry cybersecurity obligations, so the personnel lifecycle enforces them rather than relying on separate reminders.",
        "checklist": [
            "Employment terms containing security obligations",
            "Screening records appropriate to role sensitivity",
            "Offboarding checklist covering access revocation and asset return",
        ],
        "crosswalk": ["A.6.1", "A.6.2", "A.6.3", "A.6.4", "A.6.5", "A.6.6"],
    },
    # ═══ GOVERN ▸ Policy ═════════════════════════════════════════════════════
    "GV.PO-01": {
        "title": "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced",
        "description": "A cybersecurity policy exists, is derived from the organisation's own context rather than a template, is approved at the right level, and is actually applied.",
        "checklist": [
            "Approved cybersecurity policy showing version and approval date",
            "Evidence of publication and communication to those it binds",
            "Examples of the policy being enforced in a real decision",
        ],
        "crosswalk": ["A.5.1", "A.5.37"],
    },
    "GV.PO-02": {
        "title": "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission",
        "description": "The policy is revisited on a schedule and after significant change, so it continues to describe how the organisation actually operates rather than how it operated when the policy was written.",
        "checklist": [
            "Policy review schedule and record of the last review",
            "Change log showing revisions and their triggers",
            "Evidence updates were re-communicated",
        ],
        "crosswalk": ["A.5.1", "A.5.36"],
    },
    # ═══ GOVERN ▸ Oversight ══════════════════════════════════════════════════
    "GV.OV-01": {
        "title": "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction",
        "description": "The results the strategy produced are examined against what it set out to achieve, so direction is set from measured outcomes rather than from activity counts.",
        "checklist": [
            "Review record comparing outcomes against stated objectives",
            "Metrics or KPIs used in the review",
            "Decisions taken as a result of the review",
        ],
        "crosswalk": ["A.5.35", "A.5.36"],
    },
    "GV.OV-02": {
        "title": "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks",
        "description": "The strategy is checked for gaps against the organisation's current requirements and risk register, so changes in the business are reflected before they become exposures.",
        "checklist": [
            "Coverage assessment of the strategy against the risk register",
            "Record of identified gaps and remediation plans",
            "Evidence of independent or second-line review",
        ],
        "crosswalk": ["A.5.35"],
    },
    "GV.OV-03": {
        "title": "Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed",
        "description": "Programme performance is measured and reviewed by people with the authority to change it, so persistent underperformance results in an adjustment rather than a repeated report.",
        "checklist": [
            "Defined performance measures for the cybersecurity programme",
            "Management review minutes covering those measures",
            "Adjustments made in response to performance findings",
        ],
        "crosswalk": ["A.5.35", "A.5.36"],
    },
    # ═══ GOVERN ▸ Cybersecurity Supply Chain Risk Management ═════════════════
    "GV.SC-01": {
        "title": "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders",
        "description": "Supply chain cybersecurity is run as a named programme with its own objectives and owners, rather than as a clause appearing in individual contracts.",
        "checklist": [
            "Approved supply chain cybersecurity policy or programme charter",
            "Named programme owner and governance forum",
            "Documented processes covering supplier onboarding through exit",
        ],
        "crosswalk": ["A.5.19", "A.5.20", "A.5.21"],
    },
    "GV.SC-02": {
        "title": "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally",
        "description": "Who is responsible for which control is agreed with each third party and known on both sides, so no control is left assumed to be the other party's job.",
        "checklist": [
            "Responsibility matrix agreed with key suppliers or partners",
            "Evidence the split was communicated to both sides",
            "Named internal owner for each third-party relationship",
        ],
        "crosswalk": ["A.5.19", "A.5.20"],
    },
    "GV.SC-03": {
        "title": "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes",
        "description": "Supplier risk is assessed, recorded and improved through the same processes as internal risk, so it is ranked against internal exposures rather than tracked separately.",
        "checklist": [
            "Supplier risks present in the enterprise or cyber risk register",
            "Evidence supplier risk uses the standard assessment method",
            "Improvement actions tracked to closure",
        ],
        "crosswalk": ["A.5.19", "A.5.21"],
    },
    "GV.SC-04": {
        "title": "Suppliers are known and prioritized by criticality",
        "description": "A current supplier inventory exists with an agreed criticality rating, so assurance effort is concentrated on the suppliers whose failure would matter most.",
        "checklist": [
            "Supplier inventory with criticality or tier assigned",
            "Documented criteria used to assign criticality",
            "Evidence the inventory is kept current",
        ],
        "crosswalk": ["A.5.19", "A.5.21"],
    },
    "GV.SC-05": {
        "title": "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties",
        "description": "Security requirements are written into the agreement rather than requested afterwards, so they are enforceable and priced in.",
        "checklist": [
            "Standard security clauses or schedule used in supplier contracts",
            "Sample executed contracts containing the clauses",
            "Evidence requirements are tailored to supplier criticality",
        ],
        "crosswalk": ["A.5.20", "A.5.21"],
    },
    "GV.SC-06": {
        "title": "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships",
        "description": "Prospective suppliers are assessed before signature, while the organisation still has the leverage to require change or walk away.",
        "checklist": [
            "Pre-contract due diligence questionnaires or assessment reports",
            "Record of findings and how they were resolved before signature",
            "Approval record for onboarding the supplier",
        ],
        "crosswalk": ["A.5.19", "A.5.20"],
    },
    "GV.SC-07": {
        "title": "The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship",
        "description": "Supplier risk is re-assessed through the life of the relationship rather than only at onboarding, so a supplier's deterioration is noticed while the contract is still live.",
        "checklist": [
            "Ongoing supplier risk assessments with dates",
            "Monitoring evidence such as assurance reports or attestations",
            "Record of risk responses agreed with the supplier",
        ],
        "crosswalk": ["A.5.21", "A.5.22"],
    },
    "GV.SC-08": {
        "title": "Relevant suppliers and other third parties are included in incident planning, response, and recovery activities",
        "description": "Suppliers whose systems or staff would be involved in an incident are named in the plan and have taken part in exercising it, so first contact is not made during the incident.",
        "checklist": [
            "Incident response plan naming supplier roles and contacts",
            "Evidence suppliers participated in an exercise or test",
            "Agreed notification obligations and timescales",
        ],
        "crosswalk": ["A.5.22", "A.5.24"],
    },
    "GV.SC-09": {
        "title": "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle",
        "description": "Supply chain controls are measured and reported like any other control set, across the whole life of the product or service rather than at procurement only.",
        "checklist": [
            "Defined supply chain security measures and reporting cadence",
            "Performance reports covering live supplier relationships",
            "Evidence of action taken when performance fell short",
        ],
        "crosswalk": ["A.5.22", "A.5.23"],
    },
    "GV.SC-10": {
        "title": "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement",
        "description": "Exit is planned in advance - data return or destruction, access revocation, key rotation, transition support - so ending a relationship does not leave residual access or stranded data.",
        "checklist": [
            "Documented supplier offboarding or exit procedure",
            "Contract provisions covering data return and destruction",
            "Completed offboarding records for a terminated supplier",
        ],
        "crosswalk": ["A.5.22", "A.6.5"],
    },
    # ═══ IDENTIFY ▸ Asset Management ═════════════════════════════════════════
    "ID.AM-01": {
        "title": "Inventories of hardware managed by the organization are maintained",
        "description": "A current record of the physical devices the organisation manages exists and is kept current, because no other control can be applied consistently to equipment nobody knows about.",
        "checklist": [
            "Hardware asset inventory with owner and location per device",
            "Documented process and cadence for keeping it current",
            "Reconciliation between the inventory and a discovery scan",
        ],
        "crosswalk": ["A.5.9", "A.7.9"],
    },
    "ID.AM-02": {
        "title": "Inventories of software, services, and systems managed by the organization are maintained",
        "description": "A current record of installed software, subscribed services and operated systems exists, so patching, licensing and end-of-life decisions have something to work from.",
        "checklist": [
            "Software and service inventory with version and owner",
            "Documented process for adding and retiring entries",
            "Reconciliation between the inventory and a credentialed collection run",
        ],
        "crosswalk": ["A.5.9", "A.8.19"],
    },
    "ID.AM-03": {
        "title": "Representations of the organization's authorized network communication and internal and external network data flows are maintained",
        "description": "The communication the organisation intends to permit is documented, so observed traffic and exposed services can be compared against an authorised baseline instead of being judged case by case.",
        "checklist": [
            "Current network diagram showing zones and trust boundaries",
            "Documented authorised flows, including external connections",
            "Evidence observed services were reconciled against the authorised set",
        ],
        "crosswalk": ["A.8.20", "A.8.21", "A.8.22"],
    },
    "ID.AM-04": {
        "title": "Inventories of services provided by suppliers are maintained",
        "description": "The services the organisation consumes from third parties are inventoried with their owners and data exposure, so supply chain risk has a concrete scope.",
        "checklist": [
            "Inventory of supplier-provided services with internal owner",
            "Data types and systems each service touches",
            "Evidence the inventory is reviewed on a defined cycle",
        ],
        "crosswalk": ["A.5.19", "A.5.21", "A.5.23"],
    },
    "ID.AM-05": {
        "title": "Assets are prioritized based on classification, criticality, resources, and impact on the mission",
        "description": "Assets carry an agreed classification and criticality, so protection effort and incident priority follow business impact rather than technical convenience.",
        "checklist": [
            "Documented classification and criticality scheme",
            "Assets in the inventory carrying an assigned rating",
            "Evidence ratings drive handling or protection decisions",
        ],
        "crosswalk": ["A.5.9", "A.5.12", "A.5.13"],
    },
    "ID.AM-07": {
        "title": "Inventories of data and corresponding metadata for designated data types are maintained",
        "description": "The organisation knows which designated data types it holds, where they live and who owns them, which is what makes retention, classification and breach scoping possible.",
        "checklist": [
            "Data inventory or record of processing per designated data type",
            "Storage locations and named data owners",
            "Evidence the inventory is refreshed when systems change",
        ],
        "crosswalk": ["A.5.9", "A.5.12", "A.5.13"],
    },
    "ID.AM-08": {
        "title": "Systems, hardware, software, services, and data are managed throughout their life cycles",
        "description": "Assets are governed from acquisition to secure disposal, so end-of-life equipment and unsupported software are retired deliberately rather than left in place.",
        "checklist": [
            "Documented asset lifecycle procedure covering acquisition to disposal",
            "Records of secure disposal or media sanitisation",
            "Register of end-of-life or unsupported assets and their plan",
        ],
        "crosswalk": ["A.5.9", "A.5.10", "A.5.11", "A.7.14", "A.8.10"],
    },
    # ═══ IDENTIFY ▸ Risk Assessment ══════════════════════════════════════════
    "ID.RA-01": {
        "title": "Vulnerabilities in assets are identified, validated, and recorded",
        "description": "Vulnerabilities are found by a repeatable process, confirmed rather than assumed, and recorded so their treatment can be tracked to closure.",
        "checklist": [
            "Recent authenticated vulnerability scan results",
            "Evidence findings were validated rather than accepted from the tool",
            "Vulnerability register showing status and owner",
        ],
        "crosswalk": ["A.8.8"],
    },
    "ID.RA-02": {
        "title": "Cyber threat intelligence is received from information sharing forums and sources",
        "description": "The organisation subscribes to threat sources relevant to its sector and technology, so it learns about active threats from somewhere other than its own incidents.",
        "checklist": [
            "List of subscribed threat intelligence sources or sharing groups",
            "Evidence intelligence reaches a named recipient and is triaged",
            "Example of intelligence that changed a control or priority",
        ],
        "crosswalk": ["A.5.7"],
    },
    "ID.RA-03": {
        "title": "Internal and external threats to the organization are identified and recorded",
        "description": "Threats specific to this organisation - not a generic list - are identified and recorded, so risk assessment starts from a considered threat picture.",
        "checklist": [
            "Threat register or threat assessment covering internal and external actors",
            "Evidence the assessment is specific to the organisation's context",
            "Record of the most recent refresh",
        ],
        "crosswalk": ["A.5.7"],
    },
    "ID.RA-04": {
        "title": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded",
        "description": "Each credible threat-vulnerability pair carries a recorded impact and likelihood, which is what turns a vulnerability list into something that can be prioritised.",
        "checklist": [
            "Risk assessment records showing impact and likelihood per scenario",
            "Documented basis for the ratings assigned",
            "Evidence assessments are updated as the environment changes",
        ],
        "crosswalk": ["A.5.7"],
    },
    "ID.RA-05": {
        "title": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization",
        "description": "The recorded factors are combined into an inherent risk position that visibly drives what gets fixed first.",
        "checklist": [
            "Prioritised risk register derived from the assessment inputs",
            "Documented prioritisation criteria",
            "Evidence the priority order drove remediation scheduling",
        ],
        "crosswalk": ["A.5.7"],
    },
    "ID.RA-06": {
        "title": "Risk responses are chosen, prioritized, planned, tracked, and communicated",
        "description": "Each accepted risk has a chosen response with an owner and a date, and progress against it is visible, so treatment is tracked rather than assumed.",
        "checklist": [
            "Risk treatment plan with owners and target dates",
            "Evidence of tracking to closure, including overdue items",
            "Outstanding critical and high vulnerability counts trending down",
        ],
        "crosswalk": ["A.5.7", "A.8.8"],
    },
    "ID.RA-07": {
        "title": "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked",
        "description": "Changes and approved deviations are assessed for security impact before they land and are recorded with an expiry, so exceptions do not quietly become the standard.",
        "checklist": [
            "Change records showing security impact assessment",
            "Exception register with justification, approver and expiry",
            "Evidence expired exceptions are chased",
        ],
        "crosswalk": ["A.8.32"],
    },
    "ID.RA-08": {
        "title": "Processes for receiving, analyzing, and responding to vulnerability disclosures are established",
        "description": "An external finder has a published, monitored route to report a vulnerability, and reports received that way are triaged like any other finding.",
        "checklist": [
            "Published vulnerability disclosure policy and contact address",
            "Records of disclosures received and their triage",
            "Defined acknowledgement and response timescales",
        ],
        "crosswalk": ["A.5.5", "A.5.6", "A.6.8"],
    },
    "ID.RA-09": {
        "title": "The authenticity and integrity of hardware and software are assessed prior to acquisition and use",
        "description": "Hardware and software are checked for authenticity and integrity before deployment - signatures, checksums, trusted sourcing - so tampering is caught before it is trusted.",
        "checklist": [
            "Documented verification procedure for new hardware and software",
            "Evidence of signature or checksum verification for recent acquisitions",
            "Approved-source list or equivalent procurement control",
        ],
        "crosswalk": ["A.5.20", "A.8.19", "A.8.31"],
    },
    "ID.RA-10": {
        "title": "Critical suppliers are assessed prior to acquisition",
        "description": "Suppliers rated critical are security-assessed before the organisation commits, so a supplier's weaknesses are known while there is still a choice.",
        "checklist": [
            "Pre-acquisition security assessments for critical suppliers",
            "Documented assessment criteria and pass threshold",
            "Approval records referencing the assessment outcome",
        ],
        "crosswalk": ["A.5.19", "A.5.21"],
    },
    # ═══ IDENTIFY ▸ Improvement ══════════════════════════════════════════════
    "ID.IM-01": {
        "title": "Improvements are identified from evaluations",
        "description": "Audits, assessments and self-evaluations produce recorded improvement actions rather than reports that are read and filed.",
        "checklist": [
            "Recent evaluation or audit reports",
            "Improvement actions raised from them, with owners",
            "Evidence actions are tracked to closure",
        ],
        "crosswalk": ["A.5.35", "A.5.36"],
    },
    "ID.IM-02": {
        "title": "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties",
        "description": "Penetration tests, tabletop exercises and recovery tests feed a recorded improvement backlog, including where the finding involves a supplier.",
        "checklist": [
            "Reports from recent tests or exercises",
            "Improvement actions traced back to specific test findings",
            "Evidence suppliers were included where relevant",
        ],
        "crosswalk": ["A.5.27", "A.5.35", "A.8.34"],
    },
    "ID.IM-03": {
        "title": "Improvements are identified from execution of operational processes, procedures, and activities",
        "description": "Day-to-day operation - not only incidents and audits - is treated as a source of improvement, so friction and near-misses are captured while they are still cheap to fix.",
        "checklist": [
            "Mechanism for staff to raise process improvements",
            "Improvement items originating from routine operations",
            "Evidence items are reviewed and dispositioned",
        ],
        "crosswalk": ["A.5.27", "A.5.37"],
    },
    "ID.IM-04": {
        "title": "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved",
        "description": "The plans people are expected to follow under pressure exist, are known to them, and are revised after each use or exercise.",
        "checklist": [
            "Current incident response, continuity and recovery plans",
            "Evidence the plans were distributed to the roles they name",
            "Revision history showing updates after incidents or exercises",
        ],
        "crosswalk": ["A.5.24", "A.5.29", "A.5.30"],
    },
    # ═══ PROTECT ▸ Identity Management, Authentication, and Access Control ═══
    "PR.AA-01": {
        "title": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
        "description": "Accounts and credentials for people, services and devices are issued, changed and revoked through a controlled process, with credential strength enforced by configuration rather than by request.",
        "checklist": [
            "Documented joiner, mover and leaver procedure",
            "Enforced password policy showing length and complexity settings",
            "Register of service and machine accounts with owners",
        ],
        "crosswalk": ["A.5.16", "A.5.17", "A.8.5"],
    },
    "PR.AA-02": {
        "title": "Identities are proofed and bound to credentials based on the context of interactions",
        "description": "The strength of identity proofing matches what the identity will be able to do, so a privileged account is not issued on the same evidence as a guest one.",
        "checklist": [
            "Documented identity proofing requirements by account type",
            "Records of proofing performed for recent privileged accounts",
            "Evidence proofing strength is reviewed against account privilege",
        ],
        "crosswalk": ["A.5.16", "A.5.17"],
    },
    "PR.AA-03": {
        "title": "Users, services, and hardware are authenticated",
        "description": "Access requires authentication appropriate to the risk, with multi-factor authentication where the exposure warrants it, and the settings are verifiable on the host.",
        "checklist": [
            "Authentication policy stating where MFA is required",
            "Host configuration showing enforced authentication settings",
            "Evidence of lockout thresholds on repeated failure",
        ],
        "crosswalk": ["A.5.17", "A.8.5"],
    },
    "PR.AA-04": {
        "title": "Identity assertions are protected, conveyed, and verified",
        "description": "Tokens, tickets and session assertions are transmitted over protected channels and validated on receipt, so an authenticated session cannot be replayed or forged in transit.",
        "checklist": [
            "Federation or SSO configuration showing signed, encrypted assertions",
            "Evidence assertion transport uses current TLS with strong ciphers",
            "Session validation and expiry settings",
        ],
        "crosswalk": ["A.5.17", "A.8.5", "A.8.24"],
    },
    "PR.AA-05": {
        "title": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties",
        "description": "Entitlements follow a written policy, grant the least privilege that works, keep incompatible duties apart, and are re-reviewed rather than accumulating.",
        "checklist": [
            "Access control policy covering least privilege and separation of duties",
            "Evidence of periodic entitlement review with removals actioned",
            "Privileged account list showing restricted membership and MFA",
        ],
        "crosswalk": ["A.5.15", "A.5.18", "A.8.2"],
    },
    "PR.AA-06": {
        "title": "Physical access to assets is managed, monitored, and enforced commensurate with risk",
        "description": "Physical entry to areas holding sensitive assets is controlled, logged and reviewed in proportion to what those areas contain.",
        "checklist": [
            "Defined secure areas with entry control mechanisms",
            "Access logs for secure areas and evidence of review",
            "Visitor procedure including escort and record keeping",
        ],
        "crosswalk": ["A.7.1", "A.7.2", "A.7.3", "A.7.4"],
    },
    # ═══ PROTECT ▸ Awareness and Training ════════════════════════════════════
    "PR.AT-01": {
        "title": "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind",
        "description": "Everyone receives awareness training appropriate to their work, refreshed on a cycle, and the organisation can show who has completed it.",
        "checklist": [
            "Awareness programme content and schedule",
            "Completion records covering current staff and contractors",
            "Evidence of refresher training on a defined cycle",
        ],
        "crosswalk": ["A.6.3"],
    },
    "PR.AT-02": {
        "title": "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind",
        "description": "People holding security-significant roles get training specific to those duties, beyond the general awareness everyone receives.",
        "checklist": [
            "List of specialised roles and their training requirements",
            "Completion or certification records for role holders",
            "Evidence requirements are revisited as roles change",
        ],
        "crosswalk": ["A.6.3"],
    },
    # ═══ PROTECT ▸ Data Security ═════════════════════════════════════════════
    "PR.DS-01": {
        "title": "The confidentiality, integrity, and availability of data-at-rest are protected",
        "description": "Stored data is encrypted or otherwise protected in proportion to its classification, and the protection is verifiable on the host rather than asserted in a policy.",
        "checklist": [
            "Encryption standard stating where data-at-rest encryption is required",
            "Host evidence that volume or disk encryption is enabled",
            "Key management procedure covering storage and rotation",
        ],
        "crosswalk": ["A.8.1", "A.8.24"],
    },
    "PR.DS-02": {
        "title": "The confidentiality, integrity, and availability of data-in-transit are protected",
        "description": "Data crossing a network is carried over current, correctly configured transport encryption, and legacy protocols that would silently downgrade it are disabled.",
        "checklist": [
            "Transport encryption standard naming permitted protocol versions",
            "Certificate inventory showing validity and issuer",
            "Host evidence that legacy TLS and cleartext services are disabled",
        ],
        "crosswalk": ["A.8.20", "A.8.21", "A.8.24"],
    },
    "PR.DS-10": {
        "title": "The confidentiality, integrity, and availability of data-in-use are protected",
        "description": "Data being processed in memory is protected from other tenants and processes, through isolation, controlled privilege escalation, masking or equivalent measures.",
        "checklist": [
            "Documented controls protecting data during processing",
            "Evidence of memory or tenant isolation on shared platforms",
            "Data masking or minimisation applied in non-production use",
        ],
        "crosswalk": ["A.8.10", "A.8.11", "A.8.33"],
    },
    "PR.DS-11": {
        "title": "Backups of data are created, protected, maintained, and tested",
        "description": "Backups are taken on a defined schedule, protected against the same event that would take out production, and proven by restore tests rather than by the backup job reporting success.",
        "checklist": [
            "Backup policy stating scope, frequency and retention",
            "Evidence backups are protected and held separately from production",
            "Results of the most recent restore test",
        ],
        "crosswalk": ["A.8.13"],
    },
    # ═══ PROTECT ▸ Platform Security ═════════════════════════════════════════
    "PR.PS-01": {
        "title": "Configuration management practices are established and applied",
        "description": "Systems are built and kept to a documented secure baseline, and drift from it is detectable, so hardening is a maintained state rather than a build-day event.",
        "checklist": [
            "Documented hardening baselines per platform",
            "Host evidence that baseline settings are in force",
            "Process for detecting and correcting configuration drift",
        ],
        "crosswalk": ["A.8.9"],
    },
    "PR.PS-02": {
        "title": "Software is maintained, replaced, and removed commensurate with risk",
        "description": "Software is patched, upgraded or removed on a timescale set by risk, and the outstanding position is measurable rather than anecdotal.",
        "checklist": [
            "Patch policy with remediation timescales by severity",
            "Current outstanding critical and high vulnerability counts",
            "Register of unsupported software with a removal plan",
        ],
        "crosswalk": ["A.8.8", "A.8.19"],
    },
    "PR.PS-03": {
        "title": "Hardware is maintained, replaced, and removed commensurate with risk",
        "description": "Hardware is maintained, refreshed and disposed of on a risk-driven schedule, with end-of-support equipment tracked and retired rather than left running.",
        "checklist": [
            "Hardware maintenance and refresh schedule",
            "Register of end-of-support hardware with replacement plans",
            "Secure disposal records for retired equipment",
        ],
        "crosswalk": ["A.7.13", "A.7.14", "A.8.19"],
    },
    "PR.PS-04": {
        "title": "Log records are generated and made available for continuous monitoring",
        "description": "Systems generate the log records monitoring depends on, keep them long enough to be useful, and make them reachable by the people and tools that analyse them.",
        "checklist": [
            "Audit and logging policy naming required event types",
            "Host evidence that audit policy is configured and retention is set",
            "Evidence logs reach a central collector or reviewer",
        ],
        "crosswalk": ["A.8.15", "A.8.17"],
    },
    "PR.PS-05": {
        "title": "Installation and execution of unauthorized software are prevented",
        "description": "Only approved software can be installed or run, enforced technically where possible, so unapproved and unmanaged code does not reach production systems.",
        "checklist": [
            "Software allow-list or approval process",
            "Technical enforcement configuration where applied",
            "Evidence of periodic review for unauthorised installations",
        ],
        "crosswalk": ["A.8.19"],
    },
    "PR.PS-06": {
        "title": "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle",
        "description": "Security is built into how software is specified, written, reviewed and released, and the effectiveness of those practices is measured rather than assumed.",
        "checklist": [
            "Secure development policy covering the full lifecycle",
            "Evidence of security testing in the pipeline and its results",
            "Separation between development, test and production environments",
        ],
        "crosswalk": ["A.8.25", "A.8.26", "A.8.27", "A.8.28", "A.8.29", "A.8.31"],
    },
    # ═══ PROTECT ▸ Technology Infrastructure Resilience ══════════════════════
    "PR.IR-01": {
        "title": "Networks and environments are protected from unauthorized logical access and usage",
        "description": "Network access is restricted to what is authorised, environments are segregated, and the exposed service surface matches the intended design.",
        "checklist": [
            "Network segmentation design showing zones and permitted flows",
            "Firewall or access control rule set with review evidence",
            "Host evidence that unnecessary and legacy services are not listening",
        ],
        "crosswalk": ["A.8.20", "A.8.21", "A.8.22"],
    },
    "PR.IR-02": {
        "title": "The organization's technology assets are protected from environmental threats",
        "description": "Facilities holding technology assets are protected against fire, flood, power loss and similar physical hazards appropriate to their location.",
        "checklist": [
            "Environmental risk assessment for facilities holding assets",
            "Evidence of protective measures such as fire suppression and UPS",
            "Maintenance and test records for those measures",
        ],
        "crosswalk": ["A.7.5", "A.7.8", "A.7.11"],
    },
    "PR.IR-03": {
        "title": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
        "description": "Redundancy and failover exist where the recovery objectives require them, and have been proven under conditions resembling an actual failure.",
        "checklist": [
            "Documented availability and recovery objectives per service",
            "Design evidence of redundancy or failover for those services",
            "Results of the most recent failover or continuity test",
        ],
        "crosswalk": ["A.5.29", "A.5.30", "A.8.14"],
    },
    "PR.IR-04": {
        "title": "Adequate resource capacity to ensure availability is maintained",
        "description": "Compute, storage and network capacity are monitored against demand and provisioned ahead of it, so availability is not lost to predictable exhaustion.",
        "checklist": [
            "Capacity monitoring covering compute, storage and network",
            "Defined thresholds and the escalation they trigger",
            "Capacity forecast or plan supporting the next planning period",
        ],
        "crosswalk": ["A.8.6"],
    },
    # ═══ DETECT ▸ Continuous Monitoring ══════════════════════════════════════
    "DE.CM-01": {
        "title": "Networks and network services are monitored to find potentially adverse events",
        "description": "Network traffic and services are watched by a mechanism capable of raising an alert, so adverse activity is noticed by the organisation rather than reported to it.",
        "checklist": [
            "Network monitoring or IDS/IPS coverage across monitored segments",
            "Host evidence that detection agents are present and running",
            "Records of alerts raised and triaged",
        ],
        "crosswalk": ["A.8.16"],
    },
    "DE.CM-02": {
        "title": "The physical environment is monitored to find potentially adverse events",
        "description": "Physical spaces holding sensitive assets are monitored, and what the monitoring records is actually reviewed.",
        "checklist": [
            "Physical monitoring coverage such as CCTV or intrusion detection",
            "Evidence of review of physical monitoring records",
            "Procedure for responding to a physical alarm",
        ],
        "crosswalk": ["A.7.2", "A.7.4"],
    },
    "DE.CM-03": {
        "title": "Personnel activity and technology usage are monitored to find potentially adverse events",
        "description": "User and administrator activity is logged and reviewed for signs of misuse or compromise, within the bounds the organisation has told staff about.",
        "checklist": [
            "Host evidence that user and privileged activity auditing is enabled",
            "Log retention meeting the stated policy",
            "Evidence of review, alerting or anomaly detection on that activity",
        ],
        "crosswalk": ["A.8.15", "A.8.16"],
    },
    "DE.CM-06": {
        "title": "External service provider activities and services are monitored to find potentially adverse events",
        "description": "What providers do inside the organisation's environment is monitored to the same standard as internal activity, rather than trusted on the basis of the contract.",
        "checklist": [
            "Monitoring coverage over provider access and provider-run services",
            "Evidence provider activity is logged and reviewed",
            "Provider assurance reports and how they are checked",
        ],
        "crosswalk": ["A.5.22", "A.5.23", "A.8.16"],
    },
    "DE.CM-09": {
        "title": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events",
        "description": "Endpoints and servers carry monitoring that can detect malicious code and unauthorised change to files and configuration.",
        "checklist": [
            "Host evidence that anti-malware or EDR is installed and active",
            "File integrity or configuration monitoring coverage",
            "Records of detections and how they were handled",
        ],
        "crosswalk": ["A.8.7", "A.8.16"],
    },
    # ═══ DETECT ▸ Adverse Event Analysis ═════════════════════════════════════
    "DE.AE-02": {
        "title": "Potentially adverse events are analyzed to better understand associated activities",
        "description": "Alerts are analysed by someone or something able to establish what actually happened, so raw detections become findings rather than a queue.",
        "checklist": [
            "Documented triage and analysis procedure",
            "Evidence detection tooling is deployed and feeding the analysis",
            "Analysis records for a sample of recent events",
        ],
        "crosswalk": ["A.8.16"],
    },
    "DE.AE-03": {
        "title": "Information is correlated from multiple sources",
        "description": "Events from different systems are brought together so activity spanning more than one host or control can be seen as one sequence.",
        "checklist": [
            "List of log sources feeding a central collector",
            "Host evidence that auditing and retention support correlation",
            "Example of a finding that required more than one source",
        ],
        "crosswalk": ["A.8.15", "A.8.16"],
    },
    "DE.AE-04": {
        "title": "The estimated impact and scope of adverse events are understood",
        "description": "Each adverse event carries an assessment of what it reached and what it affected, which is what determines the response it receives.",
        "checklist": [
            "Impact and scope assessment recorded per significant event",
            "Documented criteria used to assess scope",
            "Evidence monitoring coverage is sufficient to establish scope",
        ],
        "crosswalk": ["A.8.16"],
    },
    "DE.AE-06": {
        "title": "Information on adverse events is provided to authorized staff and tools",
        "description": "Detections reach the people and systems that can act on them, on a timescale that still allows action.",
        "checklist": [
            "Alert routing configuration naming recipients or channels",
            "Evidence detection output reaches those recipients",
            "Records showing acknowledgement and response times",
        ],
        "crosswalk": ["A.8.16"],
    },
    "DE.AE-07": {
        "title": "Cyber threat intelligence and other contextual information are integrated into the analysis",
        "description": "Threat intelligence and asset context are available to the analysis step, so an alert is judged against what is known about the threat and the asset.",
        "checklist": [
            "Threat intelligence feeds integrated into detection or analysis",
            "Evidence asset criticality is available to analysts",
            "Example of intelligence changing the disposition of an alert",
        ],
        "crosswalk": ["A.5.7", "A.8.16"],
    },
    "DE.AE-08": {
        "title": "Incidents are declared when adverse events meet the defined incident criteria",
        "description": "Written criteria decide when an event becomes an incident, so declaration is consistent rather than dependent on who is on shift.",
        "checklist": [
            "Documented incident declaration criteria and severity levels",
            "Evidence the criteria were applied to recent events",
            "Record of criteria review after incidents or exercises",
        ],
        "crosswalk": ["A.5.24", "A.5.25"],
    },
    # ═══ RESPOND ▸ Incident Management ═══════════════════════════════════════
    "RS.MA-01": {
        "title": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
        "description": "Declaring an incident starts a documented plan that names roles and third-party involvement, so response follows a plan rather than being improvised.",
        "checklist": [
            "Current incident response plan with named roles",
            "Execution records or after-action reports from a real incident",
            "Third-party contacts and their agreed involvement",
        ],
        "crosswalk": ["A.5.24", "A.5.26"],
    },
    "RS.MA-02": {
        "title": "Incident reports are triaged and validated",
        "description": "Reports are checked and confirmed before response effort is committed, so false reports are filtered and genuine ones are not dismissed.",
        "checklist": [
            "Documented triage and validation procedure",
            "Triage records showing the validation decision",
            "Defined triage timescales and evidence they are met",
        ],
        "crosswalk": ["A.5.25", "A.5.26"],
    },
    "RS.MA-03": {
        "title": "Incidents are categorized and prioritized",
        "description": "Incidents receive a category and priority from published criteria, so response effort matches severity consistently.",
        "checklist": [
            "Incident categorisation and severity matrix",
            "Recent incidents showing assigned category and priority",
            "Evidence priority drove the response actually given",
        ],
        "crosswalk": ["A.5.25"],
    },
    "RS.MA-04": {
        "title": "Incidents are escalated or elevated as needed",
        "description": "Defined triggers escalate an incident to more senior or specialist responders, so a response that is not working is raised rather than persisted with.",
        "checklist": [
            "Documented escalation criteria and escalation path",
            "Records of incidents escalated and when",
            "Evidence escalation contacts are current",
        ],
        "crosswalk": ["A.5.24", "A.5.25"],
    },
    "RS.MA-05": {
        "title": "The criteria for initiating incident recovery are applied",
        "description": "Recovery starts on stated criteria rather than on impatience, so systems are not restored while the cause is still present.",
        "checklist": [
            "Documented criteria for moving from response to recovery",
            "Records showing the criteria were applied to a real incident",
            "Named authority for the recovery decision",
        ],
        "crosswalk": ["A.5.26", "A.5.29"],
    },
    # ═══ RESPOND ▸ Incident Analysis ═════════════════════════════════════════
    "RS.AN-03": {
        "title": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident",
        "description": "Investigation establishes the sequence of events and the underlying cause, so remediation addresses the cause rather than the symptom.",
        "checklist": [
            "Investigation records establishing timeline and root cause",
            "Log sources and retention sufficient to reconstruct the timeline",
            "Corrective actions traced to the identified cause",
        ],
        "crosswalk": ["A.5.27", "A.5.28", "A.8.15"],
    },
    "RS.AN-06": {
        "title": "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved",
        "description": "What responders did, when and on whose authority is recorded in a form that stands up later, so the response itself can be reviewed or relied on as evidence.",
        "checklist": [
            "Investigation action log with timestamps and actor",
            "Host evidence that audit logging and retention are configured",
            "Controls protecting those records from alteration",
        ],
        "crosswalk": ["A.5.28", "A.8.15"],
    },
    "RS.AN-07": {
        "title": "Incident data and metadata are collected, and their integrity and provenance are preserved",
        "description": "Evidence is collected and handled so that its origin and integrity can be demonstrated, which is what makes it usable in a legal or regulatory process.",
        "checklist": [
            "Evidence handling and chain-of-custody procedure",
            "Collected artefacts with hashes or equivalent integrity proof",
            "Log retention sufficient to cover the investigation window",
        ],
        "crosswalk": ["A.5.28", "A.8.15"],
    },
    "RS.AN-08": {
        "title": "An incident's magnitude is estimated and validated",
        "description": "How far an incident actually reached is estimated and then confirmed, so notification, recovery and reporting decisions rest on a checked figure rather than a first impression.",
        "checklist": [
            "Recorded magnitude or scope estimate per significant incident",
            "Evidence the estimate was validated against collected data",
            "Post-incident review confirming or correcting the estimate",
        ],
        "crosswalk": ["A.5.25", "A.5.27"],
    },
    # ═══ RESPOND ▸ Incident Response Reporting and Communication ═════════════
    "RS.CO-02": {
        "title": "Internal and external stakeholders are notified of incidents",
        "description": "The parties who need to know are told within the timescales the organisation is bound to, including regulators and affected individuals where that applies.",
        "checklist": [
            "Notification matrix naming parties and statutory timescales",
            "Records of notifications sent for recent incidents",
            "Evidence contact details are kept current",
        ],
        "crosswalk": ["A.5.5", "A.5.6", "A.5.24"],
    },
    "RS.CO-03": {
        "title": "Information is shared with designated internal and external stakeholders",
        "description": "Incident information is shared with the designated recipients - including sharing communities where relevant - under rules that control what may be disclosed.",
        "checklist": [
            "Information sharing policy including handling restrictions",
            "Records of information shared and with whom",
            "Membership of any sharing community relied upon",
        ],
        "crosswalk": ["A.5.6", "A.5.26"],
    },
    # ═══ RESPOND ▸ Incident Mitigation ═══════════════════════════════════════
    "RS.MI-01": {
        "title": "Incidents are contained",
        "description": "Containment stops the incident spreading while preserving what the investigation will need, which is a trade-off that has to be decided deliberately.",
        "checklist": [
            "Documented containment options and decision criteria",
            "Records of containment actions taken and their timing",
            "Evidence containment preserved required evidence",
        ],
        "crosswalk": ["A.5.26"],
    },
    "RS.MI-02": {
        "title": "Incidents are eradicated",
        "description": "The cause and any attacker foothold are removed and their absence confirmed, so recovery does not restore the problem along with the service.",
        "checklist": [
            "Eradication actions recorded per incident",
            "Host evidence that malicious code protection is active and clean",
            "Verification that the cause is no longer present",
        ],
        "crosswalk": ["A.5.26", "A.8.7"],
    },
    # ═══ RECOVER ▸ Incident Recovery Plan Execution ══════════════════════════
    "RC.RP-01": {
        "title": "The recovery portion of the incident response plan is executed once initiated from the incident response process",
        "description": "Recovery runs from a written plan that the response process hands over to, so restoration is ordered rather than opportunistic.",
        "checklist": [
            "Recovery plan with defined roles and sequence",
            "Records of recovery execution for a real incident or test",
            "Evidence the handover from response to recovery was authorised",
        ],
        "crosswalk": ["A.5.29", "A.5.30"],
    },
    "RC.RP-02": {
        "title": "Recovery actions are selected, scoped, prioritized, and performed",
        "description": "Which systems come back, in what order and to what state is decided against business priority rather than technical convenience.",
        "checklist": [
            "Recovery prioritisation based on service criticality",
            "Recovery runbooks or scoped action lists",
            "Records showing the order actually followed",
        ],
        "crosswalk": ["A.5.29", "A.5.30"],
    },
    "RC.RP-03": {
        "title": "The integrity of backups and other restoration assets is verified before using them for restoration",
        "description": "Backups and images are checked before they are trusted, so a compromised or corrupt restore point is not the thing that comes back.",
        "checklist": [
            "Backup integrity verification procedure",
            "Verification records from the most recent restore or test",
            "Evidence restore points are checked against the incident timeline",
        ],
        "crosswalk": ["A.8.13"],
    },
    "RC.RP-04": {
        "title": "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms",
        "description": "The state the organisation returns to is chosen deliberately, taking account of mission needs and the risk position the incident revealed.",
        "checklist": [
            "Record of the agreed post-incident operating state",
            "Evidence mission priorities informed that decision",
            "Risk decisions carried forward from the incident",
        ],
        "crosswalk": ["A.5.29", "A.5.30"],
    },
    "RC.RP-05": {
        "title": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed",
        "description": "Restored systems are checked for integrity and monitored before being declared normal, so a clean restoration is demonstrated rather than assumed.",
        "checklist": [
            "Post-restoration integrity verification records",
            "Host evidence that monitoring is active on restored systems",
            "Sign-off confirming return to normal operating status",
        ],
        "crosswalk": ["A.5.29", "A.8.16"],
    },
    "RC.RP-06": {
        "title": "The end of incident recovery is declared based on criteria, and incident-related documentation is completed",
        "description": "Recovery is formally closed against stated criteria and the record is completed, so the incident has a defined end and a usable history.",
        "checklist": [
            "Documented criteria for declaring recovery complete",
            "Closure records and completed incident documentation",
            "Post-incident review referencing the closed record",
        ],
        "crosswalk": ["A.5.27", "A.5.29"],
    },
    # ═══ RECOVER ▸ Incident Recovery Communication ═══════════════════════════
    "RC.CO-03": {
        "title": "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders",
        "description": "Stakeholders are kept informed of recovery progress on an agreed cadence, so the organisation controls the account of its own recovery.",
        "checklist": [
            "Recovery communication plan naming audiences and cadence",
            "Records of updates issued during a real incident or exercise",
            "Evidence contact lists are current",
        ],
        "crosswalk": ["A.5.26", "A.5.29"],
    },
    "RC.CO-04": {
        "title": "Public updates on incident recovery are shared using approved methods and messaging",
        "description": "Public statements go out through approved channels and approved wording, so external communication is accurate and consistent under pressure.",
        "checklist": [
            "Approved public communication procedure and spokespersons",
            "Pre-approved message templates or holding statements",
            "Records of public updates issued and their approval",
        ],
        "crosswalk": ["A.5.6", "A.5.26"],
    },
}
