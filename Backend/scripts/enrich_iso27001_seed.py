"""
Script: enrich_iso27001_seed.py
Purpose: Fill in the ISO/IEC 27001:2022 Annex A catalogue — control objectives,
         audit evidence checklists and framework crosswalks — and rewrite
         iso27001_2022_controls_seed.json in place.
Usage:   python -m scripts.enrich_iso27001_seed

Why this exists
───────────────
ISO 27001 shipped as the thinnest of the thirteen seeded frameworks: 0 of 93
controls carried a crosswalk, 0 carried an evidence checklist, and 82 of 93 had
their own title repeated back as the description. Every other framework in the
catalogue ships all three.

That is not cosmetic. 63 of the 93 Annex A controls can only ever be satisfied
by human attestation, and the evidence checklist is the entire prompt the
reviewer works from — an empty checklist means the attestation modal asks for a
status and a free-text note and nothing else. The crosswalk is what
`/compliance/gap-analysis` reads to answer "we are ISO-certified, where does
that leave us against NIST CSF", and with an empty crosswalk ISO could be a
gap-analysis *source* but never a target.

Descriptions here are written from scratch as statements of each control's
objective. They are deliberately not transcriptions of the standard's own text,
which is copyrighted; an organisation running a certification audit reads the
control text from its own licensed copy of ISO/IEC 27001:2022. What is captured
is what the control is *for*, which is what a reviewer needs on screen while
deciding whether their evidence satisfies it.

Crosswalk entries use the "FRAMEWORK:control" form the gap-analysis endpoint
already parses.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─────────────────────────────────────────────────────────────────────────────
# Per-control enrichment: (description, evidence_checklist, crosswalk)
# ─────────────────────────────────────────────────────────────────────────────

ENRICHMENT: dict[str, dict] = {
    # ── 5. Organizational controls ──────────────────────────────────────────
    "5.1": {
        "description": "An information security policy and its supporting topic-specific policies are defined, approved by management, published, communicated to everyone they apply to, and reviewed at planned intervals or after significant change.",
        "evidence_checklist": [
            "Approved information security policy document, showing version and approval date",
            "Record of management approval (minutes, signature or workflow record)",
            "Evidence the policy was communicated to staff and contractors",
            "Record of the most recent scheduled policy review",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.PO-01", "CIS_V8_1:14.1", "SOC2_TYPE2:CC1.1"],
    },
    "5.2": {
        "description": "Information security roles and responsibilities are defined and allocated according to the organisation's needs, so that every security duty has a named owner.",
        "evidence_checklist": [
            "Documented security roles with named holders",
            "Job descriptions or role charters covering security duties",
            "Organisation chart showing security reporting lines",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-02", "SOC2_TYPE2:CC1.3"],
    },
    "5.3": {
        "description": "Conflicting duties and areas of responsibility are separated so that no single person can initiate, approve and conceal a change or transaction on their own.",
        "evidence_checklist": [
            "Segregation-of-duties matrix for security-relevant tasks",
            "Evidence that request and approval roles are held by different people",
            "Review record for combinations that could not be separated, with compensating controls",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-02", "NIST_800_53_R5:AC-5"],
    },
    "5.4": {
        "description": "Management requires all personnel to apply information security in line with the organisation's established policies and procedures.",
        "evidence_checklist": [
            "Management directive or communication requiring policy compliance",
            "Evidence of security expectations set during onboarding",
            "Record of management review of security performance",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-01", "SOC2_TYPE2:CC1.1"],
    },
    "5.5": {
        "description": "Contact with relevant authorities — regulators, law enforcement, national CERTs — is established and maintained before it is needed.",
        "evidence_checklist": [
            "List of relevant authorities with current contact details",
            "Record of the most recent contact or registration",
            "Procedure describing when and how authorities are engaged",
        ],
        "crosswalk": ["NIST_CSF_V2:RS.CO-03", "CERT_IN_2022:cert_in_ir_1"],
    },
    "5.6": {
        "description": "Contact is maintained with special interest groups, security forums and professional associations, so the organisation receives early warning and shared practice.",
        "evidence_checklist": [
            "List of security forums, ISACs or associations the organisation belongs to",
            "Evidence of current membership or subscription",
            "Example of intelligence received and acted upon",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.RA-02"],
    },
    "5.7": {
        "description": "Threat intelligence is collected and analysed to produce actionable insight, and that insight is used to inform protective measures. New in the 2022 revision.",
        "evidence_checklist": [
            "Named threat intelligence sources (commercial, open source or sector)",
            "Recent threat intelligence report or digest",
            "Evidence that intelligence changed a control, rule or priority",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.RA-02", "NIST_CSF_V2:ID.RA-03", "CIS_V8_1:7.1"],
    },
    "5.8": {
        "description": "Information security is integrated into project management, so security requirements are identified and addressed at every stage rather than retrofitted.",
        "evidence_checklist": [
            "Project methodology showing security gates or checkpoints",
            "Security requirements recorded for a recent project",
            "Evidence of a security review before a project went live",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-03", "SOC2_TYPE2:CC3.2"],
    },
    "5.9": {
        "description": "An inventory of information and other associated assets, including their owners, is developed and maintained. CCure's asset registry is the primary evidence source.",
        "evidence_checklist": [
            "Current asset inventory export with named owners",
            "Procedure for adding, updating and retiring inventory entries",
            "Date and outcome of the most recent inventory reconciliation",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.AM-01", "NIST_CSF_V2:ID.AM-02", "CIS_V8_1:1.1"],
    },
    "5.10": {
        "description": "Rules for the acceptable use of information and associated assets are identified, documented and implemented, and users are made aware of them.",
        "evidence_checklist": [
            "Acceptable use policy",
            "Record of user acknowledgement or acceptance",
            "Evidence the policy is presented during onboarding",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.PO-01", "CIS_V8_1:14.1"],
    },
    "5.11": {
        "description": "Personnel and other interested parties return all organisational assets in their possession on termination or change of employment or contract.",
        "evidence_checklist": [
            "Asset return checklist used at offboarding",
            "Completed return records for recent leavers",
            "Reconciliation between the asset register and returned equipment",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-04", "CIS_V8_1:1.1"],
    },
    "5.12": {
        "description": "Information is classified according to its confidentiality, integrity, availability and any relevant interested-party requirements.",
        "evidence_checklist": [
            "Information classification scheme with defined levels",
            "Examples of classified information assets",
            "Evidence that owners applied classification to their assets",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.AM-05", "CIS_V8_1:3.2", "GDPR:GDPR_6_7"],
    },
    "5.13": {
        "description": "Procedures for labelling information are developed and implemented in line with the classification scheme, covering both physical and electronic forms.",
        "evidence_checklist": [
            "Labelling procedure covering physical and electronic media",
            "Screenshots or samples of applied labels",
            "Evidence of user training on labelling",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.AM-05", "CIS_V8_1:3.7"],
    },
    "5.14": {
        "description": "Information transfer rules, procedures and agreements are in place for all types of transfer facility, inside the organisation and with external parties.",
        "evidence_checklist": [
            "Information transfer policy covering email, file transfer and physical media",
            "Transfer agreements with external parties",
            "Evidence that transfers use approved encrypted channels",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-02", "CIS_V8_1:3.10"],
    },
    "5.15": {
        "description": "Rules to control physical and logical access to information and associated assets are established and implemented on the basis of business and security requirements.",
        "evidence_checklist": [
            "Access control policy stating the access model in use",
            "Role-to-permission mapping",
            "Evidence of least privilege being applied to a sample of accounts",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "CIS_V8_1:6.1", "NIST_800_53_R5:AC-3"],
    },
    "5.16": {
        "description": "The full life cycle of identities is managed, from creation through change to revocation, so every identity is traceable to a responsible person.",
        "evidence_checklist": [
            "Identity lifecycle procedure covering joiners, movers and leavers",
            "Sample of account creation and revocation records",
            "Evidence that shared or generic accounts are justified and controlled",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-01", "CIS_V8_1:5.1", "NIST_800_53_R5:IA-2"],
    },
    "5.17": {
        "description": "Allocation and management of authentication information is controlled by a management process, including advising personnel on appropriate handling.",
        "evidence_checklist": [
            "Password or authentication policy stating minimum requirements",
            "Evidence of enforced policy settings on a sample of systems",
            "Procedure for issuing and resetting credentials securely",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-01", "CIS_V8_1:5.2", "NIST_800_53_R5:IA-5"],
    },
    "5.18": {
        "description": "Access rights are provisioned, reviewed, modified and removed in accordance with the access control policy, and reviewed at planned intervals.",
        "evidence_checklist": [
            "Access review procedure with defined frequency",
            "Completed access review records with reviewer sign-off",
            "Evidence that revocations identified by review were carried out",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "CIS_V8_1:6.8", "NIST_800_53_R5:AC-2"],
    },
    "5.19": {
        "description": "Processes and procedures are defined and implemented to manage the information security risks associated with the use of suppliers' products and services.",
        "evidence_checklist": [
            "Supplier security policy",
            "Supplier register with assessed risk levels",
            "Security assessment record for a recent supplier",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-01", "CIS_V8_1:15.1"],
    },
    "5.20": {
        "description": "Relevant information security requirements are established and agreed with each supplier, based on the type of relationship.",
        "evidence_checklist": [
            "Standard security clauses used in supplier contracts",
            "Signed agreement containing security requirements",
            "Evidence that requirements vary with supplier risk",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-05", "CIS_V8_1:15.4"],
    },
    "5.21": {
        "description": "Processes and procedures manage the information security risks associated with the ICT products and services supply chain.",
        "evidence_checklist": [
            "ICT supply chain risk management procedure",
            "Evidence of component or software provenance checks",
            "Assessment of a critical ICT supplier's own supply chain",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-07", "NIST_800_53_R5:SR-3"],
    },
    "5.22": {
        "description": "The organisation regularly monitors, reviews, evaluates and manages change in suppliers' information security practice and service delivery.",
        "evidence_checklist": [
            "Supplier performance and security review records",
            "Evidence of monitoring against agreed security levels",
            "Change record showing a supplier change was assessed",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-07", "CIS_V8_1:15.5"],
    },
    "5.23": {
        "description": "Processes for acquiring, using, managing and exiting cloud services are established in accordance with the organisation's security requirements.",
        "evidence_checklist": [
            "Cloud service register with owners and data classifications",
            "Cloud security configuration baseline or benchmark results",
            "Documented exit or portability plan for a critical cloud service",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-06", "CIS_V8_1:15.2"],
    },
    "5.24": {
        "description": "Incident management is planned and prepared: responsibilities are defined and processes are established before an incident occurs.",
        "evidence_checklist": [
            "Incident response plan with defined roles",
            "Incident classification and escalation criteria",
            "Evidence the plan has been exercised or tested",
        ],
        "crosswalk": [
            "NIST_CSF_V2:RS.MA-01",
            "CIS_V8_1:17.1",
            "CERT_IN_2022:cert_in_ir_1",
        ],
    },
    "5.25": {
        "description": "Information security events are assessed and a decision is made on whether each is to be categorised as an information security incident.",
        "evidence_checklist": [
            "Documented triage criteria distinguishing events from incidents",
            "Sample of assessed events with the resulting decision",
            "Evidence of consistent categorisation over a review period",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.AE-02", "CIS_V8_1:17.4"],
    },
    "5.26": {
        "description": "Information security incidents are responded to in accordance with the documented procedures.",
        "evidence_checklist": [
            "Incident records showing the response followed the plan",
            "Timeline of a recent incident from detection to closure",
            "Evidence of containment and recovery actions taken",
        ],
        "crosswalk": ["NIST_CSF_V2:RS.MA-02", "CIS_V8_1:17.7"],
    },
    "5.27": {
        "description": "Knowledge gained from information security incidents is used to strengthen and improve controls.",
        "evidence_checklist": [
            "Post-incident review or lessons-learned record",
            "Improvement actions raised from an incident, with owners",
            "Evidence that at least one action changed a control",
        ],
        "crosswalk": ["NIST_CSF_V2:RS.AN-08", "CIS_V8_1:17.8"],
    },
    "5.28": {
        "description": "Procedures are established for the identification, collection, acquisition and preservation of evidence relating to information security events.",
        "evidence_checklist": [
            "Digital evidence handling procedure",
            "Chain-of-custody record from an investigation",
            "Evidence that collection preserves integrity (hashing, write-blocking)",
        ],
        "crosswalk": ["NIST_CSF_V2:RS.AN-07", "CERT_IN_2022:cert_in_log_1"],
    },
    "5.29": {
        "description": "The organisation plans how to maintain information security at an appropriate level during disruption.",
        "evidence_checklist": [
            "Business continuity plan addressing security during disruption",
            "Evidence that security controls persist in fallback arrangements",
            "Continuity exercise record",
        ],
        "crosswalk": ["NIST_CSF_V2:RC.RP-01", "CIS_V8_1:11.1"],
    },
    "5.30": {
        "description": "ICT readiness is planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements. New in the 2022 revision.",
        "evidence_checklist": [
            "ICT continuity plan with defined RTO and RPO",
            "Most recent continuity or failover test report",
            "Evidence that test findings were remediated",
        ],
        "crosswalk": ["NIST_CSF_V2:RC.RP-01", "NIST_800_53_R5:CP-9"],
    },
    "5.31": {
        "description": "Legal, statutory, regulatory and contractual requirements relevant to information security are identified, documented and kept up to date.",
        "evidence_checklist": [
            "Register of applicable legal and regulatory obligations",
            "Date of the last review of the register",
            "Evidence of how a specific obligation is met",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.OC-03", "DPDP_2023:DPDP_1_1", "GDPR:GDPR_1_1"],
    },
    "5.32": {
        "description": "Appropriate procedures protect intellectual property rights, including those covering proprietary software licensing.",
        "evidence_checklist": [
            "Software licence register",
            "Evidence of licence compliance review",
            "Policy prohibiting unlicensed software",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.OC-03", "CIS_V8_1:2.1"],
    },
    "5.33": {
        "description": "Records are protected from loss, destruction, falsification, unauthorised access and unauthorised release.",
        "evidence_checklist": [
            "Records retention schedule",
            "Evidence of access restrictions on record stores",
            "Evidence of integrity protection or immutability where required",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-01", "SOC2_TYPE2:CC6.1"],
    },
    "5.34": {
        "description": "The organisation identifies and meets the requirements for preservation of privacy and protection of personally identifiable information under applicable law and contract.",
        "evidence_checklist": [
            "Record of processing activities",
            "Privacy notice provided to data subjects",
            "Evidence of a completed privacy impact assessment",
        ],
        "crosswalk": ["GDPR:GDPR_5_1", "DPDP_2023:DPDP_5_1", "NIST_CSF_V2:GV.OC-03"],
    },
    "5.35": {
        "description": "The organisation's approach to managing information security is independently reviewed at planned intervals and when significant change occurs.",
        "evidence_checklist": [
            "Internal audit plan and schedule",
            "Independent review or audit report",
            "Corrective actions raised and their closure status",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.OV-01", "SOC2_TYPE2:CC4.1"],
    },
    "5.36": {
        "description": "Compliance with the organisation's own information security policy, topic-specific policies, rules and standards is regularly reviewed.",
        "evidence_checklist": [
            "Compliance review schedule",
            "Review findings with identified non-conformities",
            "Evidence of remediation of non-conformities",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.OV-03", "SOC2_TYPE2:CC4.2"],
    },
    "5.37": {
        "description": "Operating procedures for information processing facilities are documented and made available to the personnel who need them.",
        "evidence_checklist": [
            "Documented operating procedures for key systems",
            "Evidence the procedures are accessible to operators",
            "Record of the most recent procedure review",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "SOC2_TYPE2:CC5.3"],
    },
    # ── 6. People controls ──────────────────────────────────────────────────
    "6.1": {
        "description": "Background verification checks on candidates are carried out before employment, proportionate to business requirements, classification of information accessed and perceived risk.",
        "evidence_checklist": [
            "Screening policy stating what checks apply to which roles",
            "Completed screening records for recent hires",
            "Evidence that screening depth scales with role sensitivity",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-04", "NIST_800_53_R5:PS-3"],
    },
    "6.2": {
        "description": "Employment contracts state the personnel's and the organisation's responsibilities for information security.",
        "evidence_checklist": [
            "Employment contract template containing security clauses",
            "Signed contract or acknowledgement from a sample of staff",
            "Equivalent clauses in contractor agreements",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-04", "NIST_800_53_R5:PS-6"],
    },
    "6.3": {
        "description": "Personnel and relevant interested parties receive appropriate security awareness education, training and regular updates relevant to their role.",
        "evidence_checklist": [
            "Security awareness training plan",
            "Completion records with dates and pass rates",
            "Evidence of role-specific training for privileged users",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AT-01", "CIS_V8_1:14.1"],
    },
    "6.4": {
        "description": "A formal and communicated disciplinary process is in place to take action against personnel who commit an information security policy violation.",
        "evidence_checklist": [
            "Documented disciplinary process referencing security violations",
            "Evidence the process was communicated to staff",
            "Record of consistent application (anonymised if necessary)",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-04", "NIST_800_53_R5:PS-8"],
    },
    "6.5": {
        "description": "Information security responsibilities that remain valid after termination or change of employment are defined, enforced and communicated.",
        "evidence_checklist": [
            "Offboarding checklist covering continuing obligations",
            "Evidence that leavers were reminded of ongoing duties",
            "Confirmation that access was revoked on the effective date",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.RR-04", "CIS_V8_1:5.3"],
    },
    "6.6": {
        "description": "Confidentiality or non-disclosure agreements reflecting the organisation's needs are identified, documented, regularly reviewed and signed.",
        "evidence_checklist": [
            "NDA template in current use",
            "Signed NDAs for staff and third parties with access",
            "Date of the last NDA template review",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-05", "SOC2_TYPE2:CC1.4"],
    },
    "6.7": {
        "description": "Security measures are implemented when personnel work remotely, to protect information accessed, processed or stored outside the organisation's premises.",
        "evidence_checklist": [
            "Remote working policy",
            "Evidence of VPN or equivalent secure access enforcement",
            "Endpoint protection and encryption status for remote devices",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "CIS_V8_1:12.7"],
    },
    "6.8": {
        "description": "A mechanism exists for personnel to report observed or suspected information security events through appropriate channels in a timely manner.",
        "evidence_checklist": [
            "Documented reporting channel and how staff are told about it",
            "Sample of reports received",
            "Evidence of acknowledgement and follow-up on reports",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.AE-03", "CIS_V8_1:17.3"],
    },
    # ── 7. Physical controls ────────────────────────────────────────────────
    "7.1": {
        "description": "Security perimeters are defined and used to protect areas that contain information and other associated assets.",
        "evidence_checklist": [
            "Site plan showing defined security perimeters",
            "Photographs or description of perimeter barriers",
            "Record of perimeter inspection",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-06", "NIST_800_53_R5:PE-3"],
    },
    "7.2": {
        "description": "Secure areas are protected by appropriate entry controls and access points, so only authorised personnel enter.",
        "evidence_checklist": [
            "Access control system configuration for secure areas",
            "Authorised access list with review date",
            "Sample of entry logs",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-06", "NIST_800_53_R5:PE-3"],
    },
    "7.3": {
        "description": "Physical security for offices, rooms and facilities is designed and implemented.",
        "evidence_checklist": [
            "Physical security standard for offices and equipment rooms",
            "Evidence of implemented measures (locks, screening, signage)",
            "Record of a physical security walkthrough",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-06", "NIST_800_53_R5:PE-5"],
    },
    "7.4": {
        "description": "Premises are continuously monitored for unauthorised physical access. New in the 2022 revision.",
        "evidence_checklist": [
            "Description of monitoring in place (CCTV, alarms, guards)",
            "Retention period and sample of monitoring records",
            "Procedure for responding to a monitoring alert",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.CM-02", "NIST_800_53_R5:PE-6"],
    },
    "7.5": {
        "description": "Protection is designed and implemented against physical and environmental threats, including natural disasters and other intentional or unintentional threats.",
        "evidence_checklist": [
            "Environmental threat assessment for each site",
            "Evidence of protective measures (fire suppression, flood defence)",
            "Test or inspection records for those measures",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-02", "NIST_800_53_R5:PE-13"],
    },
    "7.6": {
        "description": "Security measures for working in secure areas are designed and implemented.",
        "evidence_checklist": [
            "Rules for working in secure areas",
            "Evidence the rules are displayed or briefed",
            "Record of supervision or escort arrangements for visitors",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-06", "NIST_800_53_R5:PE-3"],
    },
    "7.7": {
        "description": "Clear desk rules for papers and removable storage media, and clear screen rules for information processing facilities, are defined and enforced.",
        "evidence_checklist": [
            "Clear desk and clear screen policy",
            "Evidence of enforced automatic screen lock settings",
            "Record of a clear desk inspection",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "NIST_800_53_R5:AC-11"],
    },
    "7.8": {
        "description": "Equipment is sited securely and protected from environmental threats and unauthorised access.",
        "evidence_checklist": [
            "Equipment siting standard",
            "Evidence of rack or cabinet security in equipment rooms",
            "Environmental monitoring readings for equipment areas",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-02", "NIST_800_53_R5:PE-18"],
    },
    "7.9": {
        "description": "Assets off-premises are protected, accounting for the different risks of working outside the organisation's sites.",
        "evidence_checklist": [
            "Policy covering assets taken off-site",
            "Register of off-site assets with holders",
            "Evidence of encryption and tracking on mobile devices",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-01", "CIS_V8_1:3.6"],
    },
    "7.10": {
        "description": "Storage media are managed through their life cycle of acquisition, use, transportation and disposal in accordance with the classification scheme and handling requirements.",
        "evidence_checklist": [
            "Removable media policy",
            "Media register or control mechanism",
            "Secure disposal certificates for retired media",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-01", "NIST_800_53_R5:MP-6"],
    },
    "7.11": {
        "description": "Information processing facilities are protected from power failures and other disruptions caused by failures in supporting utilities.",
        "evidence_checklist": [
            "UPS and generator inventory with capacity",
            "Most recent utility failover test record",
            "Maintenance schedule for supporting utilities",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-04", "NIST_800_53_R5:PE-11"],
    },
    "7.12": {
        "description": "Cables carrying power, data or supporting information services are protected from interception, interference or damage.",
        "evidence_checklist": [
            "Cabling standard or plan",
            "Evidence of physical protection (conduit, segregation, labelling)",
            "Inspection record for cabling routes",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-01", "NIST_800_53_R5:PE-9"],
    },
    "7.13": {
        "description": "Equipment is maintained correctly to ensure the continued availability and integrity of information.",
        "evidence_checklist": [
            "Maintenance schedule for critical equipment",
            "Maintenance records showing the schedule is followed",
            "Evidence that maintenance personnel are authorised and supervised",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "NIST_800_53_R5:MA-2"],
    },
    "7.14": {
        "description": "Items of equipment containing storage media are verified to ensure any sensitive data and licensed software has been removed or securely overwritten before disposal or re-use.",
        "evidence_checklist": [
            "Secure disposal and re-use procedure",
            "Sanitisation or destruction certificates",
            "Verification record confirming data removal before re-use",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-01", "NIST_800_53_R5:MP-6"],
    },
    # ── 8. Technological controls ───────────────────────────────────────────
    "8.1": {
        "description": "Information stored on, processed by or accessible via user endpoint devices is protected, including through endpoint hardening, disk encryption and screen locking.",
        "evidence_checklist": [
            "Endpoint hardening baseline",
            "Disk encryption status report across the endpoint estate",
            "Evidence of enforced screen lock and local administrator restrictions",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "CIS_V8_1:4.1", "NIST_800_53_R5:CM-6"],
    },
    "8.2": {
        "description": "The allocation and use of privileged access rights is restricted and managed, with privileged accounts identified, justified and reviewed.",
        "evidence_checklist": [
            "Inventory of privileged accounts with business justification",
            "Evidence of multi-factor authentication on privileged access",
            "Most recent privileged access review with sign-off",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "CIS_V8_1:5.4", "NIST_800_53_R5:AC-6"],
    },
    "8.3": {
        "description": "Access to information and other associated assets is restricted in accordance with the established access control policy.",
        "evidence_checklist": [
            "Permission matrix for key information stores",
            "Evidence of restriction testing on a sample of resources",
            "Exception register for broad access grants",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-05", "NIST_800_53_R5:AC-3"],
    },
    "8.4": {
        "description": "Read and write access to source code, development tools and software libraries is appropriately managed.",
        "evidence_checklist": [
            "Repository access list with roles",
            "Branch protection or code review enforcement settings",
            "Evidence that build systems restrict who can publish artefacts",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-06", "CIS_V8_1:16.4"],
    },
    "8.5": {
        "description": "Secure authentication technologies and procedures are implemented, based on the access restrictions and the access control policy.",
        "evidence_checklist": [
            "Authentication standard specifying minimum length and complexity",
            "Evidence of enforced password policy on a sample of hosts",
            "Multi-factor authentication coverage report",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.AA-03", "CIS_V8_1:6.3", "NIST_800_53_R5:IA-2"],
    },
    "8.6": {
        "description": "The use of resources is monitored and adjusted in line with current and expected capacity requirements.",
        "evidence_checklist": [
            "Capacity monitoring dashboards or reports",
            "Defined capacity thresholds and alerting",
            "Record of a capacity-driven change",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-04", "SOC2_TYPE2:A1.1"],
    },
    "8.7": {
        "description": "Protection against malware is implemented and supported by appropriate user awareness.",
        "evidence_checklist": [
            "Anti-malware coverage report across the estate",
            "Evidence that signatures or engines are current",
            "User awareness material covering malware",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.CM-01", "CIS_V8_1:10.1", "NIST_800_53_R5:SI-3"],
    },
    "8.8": {
        "description": "Information about technical vulnerabilities of information systems in use is obtained, exposure evaluated, and appropriate measures taken.",
        "evidence_checklist": [
            "Most recent vulnerability scan report",
            "Remediation SLA by severity and evidence of adherence",
            "Register of accepted vulnerability risks with expiry dates",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.RA-01", "CIS_V8_1:7.1", "NIST_800_53_R5:RA-5"],
    },
    "8.9": {
        "description": "Configurations, including security configurations, of hardware, software, services and networks are established, documented, implemented, monitored and reviewed.",
        "evidence_checklist": [
            "Documented secure configuration baselines per platform",
            "Compliance report against those baselines",
            "Evidence that drift is detected and corrected",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "CIS_V8_1:4.1", "NIST_800_53_R5:CM-6"],
    },
    "8.10": {
        "description": "Information stored in information systems, devices or any other storage media is deleted when no longer required. New in the 2022 revision.",
        "evidence_checklist": [
            "Data retention and deletion schedule",
            "Evidence of automated or scheduled deletion jobs",
            "Deletion certificates or logs for a recent retention cycle",
        ],
        "crosswalk": ["GDPR:GDPR_4_1", "DPDP_2023:DPDP_2_2", "NIST_CSF_V2:PR.DS-01"],
    },
    "8.11": {
        "description": "Data masking is used in accordance with the access control policy and applicable legislation, to limit exposure of sensitive data. New in the 2022 revision.",
        "evidence_checklist": [
            "Data masking or tokenisation standard",
            "Evidence of masking in non-production environments",
            "Sample showing masked output for a sensitive field",
        ],
        "crosswalk": ["GDPR:GDPR_5_2", "NIST_CSF_V2:PR.DS-01"],
    },
    "8.12": {
        "description": "Data leakage prevention measures are applied to systems, networks and devices that process, store or transmit sensitive information. New in the 2022 revision.",
        "evidence_checklist": [
            "DLP policy and the channels it covers",
            "DLP tool configuration or rule set",
            "Sample of DLP alerts and their disposition",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-02", "CIS_V8_1:3.13"],
    },
    "8.13": {
        "description": "Backup copies of information, software and systems are maintained and regularly tested in accordance with the agreed backup policy.",
        "evidence_checklist": [
            "Backup policy stating scope, frequency and retention",
            "Recent backup job success report",
            "Restore test record proving backups are usable",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-11", "CIS_V8_1:11.1", "NIST_800_53_R5:CP-9"],
    },
    "8.14": {
        "description": "Information processing facilities are implemented with sufficient redundancy to meet availability requirements.",
        "evidence_checklist": [
            "Architecture diagram showing redundant components",
            "Defined availability targets",
            "Most recent failover test result",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-03", "SOC2_TYPE2:A1.2"],
    },
    "8.15": {
        "description": "Logs recording activities, exceptions, faults and other relevant events are produced, stored, protected and analysed.",
        "evidence_checklist": [
            "Logging standard listing which events are recorded",
            "Evidence of audit policy enabled on a sample of hosts",
            "Log retention configuration and protection from tampering",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.AE-03", "CIS_V8_1:8.2", "NIST_800_53_R5:AU-6"],
    },
    "8.16": {
        "description": "Networks, systems and applications are monitored for anomalous behaviour and appropriate actions are taken to evaluate potential incidents.",
        "evidence_checklist": [
            "Description of monitoring coverage (EDR, IDS/IPS, SIEM)",
            "Sample of alerts and their triage outcome",
            "Defined thresholds for escalating an anomaly to an incident",
        ],
        "crosswalk": ["NIST_CSF_V2:DE.CM-01", "CIS_V8_1:13.1", "NIST_800_53_R5:SI-4"],
    },
    "8.17": {
        "description": "Clocks of information processing systems are synchronised to approved time sources, so that log timestamps can be correlated across systems.",
        "evidence_checklist": [
            "Approved time source list",
            "Evidence of NTP configuration on a sample of hosts",
            "Check that log timestamps agree across two systems",
        ],
        "crosswalk": [
            "NIST_CSF_V2:PR.PS-01",
            "CIS_V8_1:8.4",
            "CERT_IN_2022:cert_in_log_2",
        ],
    },
    "8.18": {
        "description": "The use of utility programs capable of overriding system and application controls is restricted and tightly controlled.",
        "evidence_checklist": [
            "List of privileged utilities in use and who may run them",
            "Evidence of restricted execution or approval workflow",
            "Log sample showing utility use is recorded",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-05", "NIST_800_53_R5:CM-7"],
    },
    "8.19": {
        "description": "Procedures and measures are implemented to securely manage software installation on operational systems.",
        "evidence_checklist": [
            "Software installation policy and approval process",
            "Application allow-list or software inventory baseline",
            "Evidence that unauthorised software is detected and removed",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "CIS_V8_1:2.5", "NIST_800_53_R5:CM-7"],
    },
    "8.20": {
        "description": "Networks and network devices are secured, managed and controlled to protect information in systems and applications.",
        "evidence_checklist": [
            "Network security architecture and firewall rule base",
            "Evidence that legacy and insecure protocols are disabled",
            "Most recent firewall rule review",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-01", "CIS_V8_1:12.2", "NIST_800_53_R5:SC-7"],
    },
    "8.21": {
        "description": "Security mechanisms, service levels and service requirements of network services are identified, implemented and monitored.",
        "evidence_checklist": [
            "Inventory of network services with their security requirements",
            "Evidence that management and database services are not exposed",
            "Service level agreements covering network security",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-01", "CIS_V8_1:12.3", "NIST_800_53_R5:SC-7"],
    },
    "8.22": {
        "description": "Groups of information services, users and information systems are segregated in the organisation's networks.",
        "evidence_checklist": [
            "Network segmentation diagram showing zones and boundaries",
            "VLAN or firewall configuration enforcing the segmentation",
            "Evidence of segmentation testing between zones",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-01", "CIS_V8_1:12.2", "IEC_62443:SR-5.1"],
    },
    "8.23": {
        "description": "Access to external websites is managed to reduce exposure to malicious content. New in the 2022 revision.",
        "evidence_checklist": [
            "Web filtering policy and blocked categories",
            "Web filter configuration or coverage report",
            "Sample of blocked-request logs",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-05", "CIS_V8_1:9.3"],
    },
    "8.24": {
        "description": "Rules for the effective use of cryptography, including cryptographic key management, are defined and implemented — covering algorithm strength, protocol versions and certificate validity.",
        "evidence_checklist": [
            "Cryptographic policy naming approved algorithms and minimum key lengths",
            "TLS configuration report showing no weak ciphers or deprecated protocols",
            "Certificate inventory with expiry dates and issuing authority",
            "Key management procedure covering generation, storage and rotation",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-02", "CIS_V8_1:3.10", "NIST_800_53_R5:SC-13"],
    },
    "8.25": {
        "description": "Rules for the secure development of software and systems are established and applied.",
        "evidence_checklist": [
            "Secure development lifecycle policy",
            "Evidence of security activities at each development stage",
            "Developer secure coding training records",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-06", "CIS_V8_1:16.1"],
    },
    "8.26": {
        "description": "Information security requirements are identified, specified and approved when developing or acquiring applications.",
        "evidence_checklist": [
            "Security requirements template for new applications",
            "Approved requirements for a recent application",
            "Evidence that requirements were verified before release",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-06", "CIS_V8_1:16.10"],
    },
    "8.27": {
        "description": "Principles for engineering secure systems are established, documented, maintained and applied to any information system development activity.",
        "evidence_checklist": [
            "Documented secure architecture principles",
            "Architecture review record for a recent system",
            "Evidence of threat modelling",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-06", "NIST_800_53_R5:SA-8"],
    },
    "8.28": {
        "description": "Secure coding principles are applied to software development. New in the 2022 revision.",
        "evidence_checklist": [
            "Secure coding standard in use",
            "Static analysis or code review results",
            "Evidence that identified coding defects were fixed",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-06", "CIS_V8_1:16.11"],
    },
    "8.29": {
        "description": "Security testing processes are defined and implemented in the development life cycle.",
        "evidence_checklist": [
            "Security test plan covering the development lifecycle",
            "Most recent penetration test or DAST report",
            "Evidence that findings were remediated before release",
        ],
        "crosswalk": ["NIST_CSF_V2:ID.RA-01", "CIS_V8_1:16.13"],
    },
    "8.30": {
        "description": "The organisation directs, monitors and reviews the activities related to outsourced system development.",
        "evidence_checklist": [
            "Contractual security requirements for outsourced development",
            "Evidence of code or security review of delivered work",
            "Acceptance testing record covering security",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.SC-05", "CIS_V8_1:16.11"],
    },
    "8.31": {
        "description": "Development, testing and production environments are separated and secured.",
        "evidence_checklist": [
            "Environment topology showing separation",
            "Evidence of distinct credentials and network boundaries per environment",
            "Change control record for promotion between environments",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.IR-01", "NIST_800_53_R5:CM-4"],
    },
    "8.32": {
        "description": "Changes to information processing facilities and information systems are subject to change management procedures.",
        "evidence_checklist": [
            "Change management procedure",
            "Sample of change records with approvals",
            "Evidence of security impact assessment within the change process",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.PS-01", "CIS_V8_1:4.2", "NIST_800_53_R5:CM-3"],
    },
    "8.33": {
        "description": "Test information is appropriately selected, protected and managed.",
        "evidence_checklist": [
            "Test data management standard",
            "Evidence that production data is masked or synthetic in test",
            "Approval record for any use of live data in testing",
        ],
        "crosswalk": ["NIST_CSF_V2:PR.DS-01", "NIST_800_53_R5:SA-3"],
    },
    "8.34": {
        "description": "Audit tests and other assurance activities involving assessment of operational systems are planned and agreed between the tester and appropriate management.",
        "evidence_checklist": [
            "Agreed audit test plan and scope",
            "Management authorisation for testing on operational systems",
            "Record of controls applied to limit disruption during testing",
        ],
        "crosswalk": ["NIST_CSF_V2:GV.OV-01", "NIST_800_53_R5:AU-5"],
    },
}

# Controls whose catalogue `scannability` overstated what the engine can
# actually verify.
#
# Eighteen controls carried `semi_auto` while having no automated rule at all —
# every one of them was covered only by a manual attestation placeholder. The
# earlier pass here downgraded A.8.19 and A.8.22 from `auto` to `semi_auto`,
# which was the right direction and not far enough: `semi_auto` is still a claim
# of partial automation, and the register, the dashboard's coverage figures and
# the SoA's "Scan Mode" column all read it as one. `test_scannability_only_
# claims_automation_that_exists` did not catch them because it only inspected
# controls marked `auto`.
#
# Four are promoted instead, because the evidence to decide them is already
# collected and simply was not wired to them — see the `rules_data` entries in
# `seed_real_rules.py` tagged ISO-ACCESS-REVIEW, ISO-BACKUP-FREQ,
# ISO-PRIV-UTILITY and ISO-SESSION-TIMEOUT.
SCANNABILITY_CORRECTIONS = {
    # Promoted: a real rule now reads a real adapter key for each of these.
    "5.18": "auto",  # account_review_completed  — access rights are reviewed
    "8.13": "auto",  # backup_frequency_days     — backups are actually taken
    "8.18": "auto",  # uac_enabled               — privilege elevation is gated
    # Demoted: nothing the collectors gather can decide these. Each needs a
    # document, a design or a human judgement.
    "5.9": "manual",  # completeness of an asset inventory is not observable
    "5.15": "manual",  # the access control *policy*, not its enforcement
    "5.16": "manual",  # identity lifecycle is a process record
    "5.17": "manual",  # allocation and handling of authentication secrets
    "5.23": "manual",  # cloud service acquisition and management
    "8.3": "manual",  # information access restriction per the policy
    "8.4": "manual",  # source code repository access
    "8.6": "manual",  # capacity planning
    "8.10": "manual",  # information deletion on request and at end of life
    "8.11": "manual",  # data masking
    "8.12": "manual",  # data leakage prevention
    "8.19": "manual",  # needs a software allow-list the collectors do not gather
    "8.22": "manual",  # needs the intended segmentation design, a human input
    "8.23": "manual",  # outbound web filtering; `waf_active` is a WAF, which is
    # an inbound control and a different thing entirely
    "8.31": "manual",  # separation of development, test and production
}

# A module name is a promise that something runs. It is set only for controls
# that reach `auto`, and cleared for the rest — A.8.19 and A.8.22 previously
# carried a hint ("Software inventory", "Network Topology") while being
# attestation-only, which reads on screen as automation that is merely not
# finished rather than automation that does not exist.
SCAN_MODULE_HINTS = {
    "5.18": "Offline Configuration Scan (access review)",
    "8.1": "Offline Configuration Scan",
    "8.2": "Credential Validation / RBAC",
    "8.5": "Credential Validation (password policy)",
    "8.7": "Malware Scan",
    "8.8": "Vulnerability Audit",
    "8.9": "Offline Configuration Scan",
    "8.13": "Offline Configuration Scan (backup frequency)",
    "8.15": "Offline Configuration Scan (audit policy, log retention)",
    "8.16": "Offline Configuration Scan (IDS/EDR presence)",
    "8.17": "Offline Configuration Scan (NTP)",
    "8.18": "Offline Configuration Scan (privilege elevation)",
    "8.20": "Services & Ports / Offline Configuration Scan",
    "8.21": "Services & Ports",
    "8.24": "TLS / Certificates",
}


def main() -> int:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "iso27001_2022_controls_seed.json")

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    missing = []
    for ctrl in data["controls"]:
        cid = str(ctrl["id"])
        enrich = ENRICHMENT.get(cid)
        if not enrich:
            missing.append(cid)
            continue

        ctrl["description"] = enrich["description"]
        ctrl["evidence_checklist"] = enrich["evidence_checklist"]
        ctrl["crosswalk"] = enrich["crosswalk"]

        if cid in SCANNABILITY_CORRECTIONS:
            ctrl["scannability"] = SCANNABILITY_CORRECTIONS[cid]

        # Set the hint where there is one, and clear it where there is not.
        # Assigning only on a hit left stale hints behind on the controls this
        # pass demoted, so a `manual` control kept advertising a scan module.
        ctrl["scan_module_hint"] = SCAN_MODULE_HINTS.get(cid)

        # `note` held developer asides ("New in 2022.", "Auto if a repo/VCS
        # integration is added later.") that the seeder promoted into
        # `description` because there was nothing better. Now that a real
        # description exists the note is redundant, and leaving it risks a
        # future seeder run preferring it again.
        ctrl.pop("note", None)

    if missing:
        print(f"ERROR: no enrichment authored for {len(missing)} controls: {missing}")
        return 1

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    total = len(data["controls"])
    print(f"Enriched {total} ISO/IEC 27001:2022 controls in {path}")
    print(
        f"  descriptions:        {sum(1 for c in data['controls'] if c.get('description'))}"
    )
    print(
        f"  evidence checklists: {sum(1 for c in data['controls'] if c.get('evidence_checklist'))}"
    )
    print(
        f"  crosswalks:          {sum(1 for c in data['controls'] if c.get('crosswalk'))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
