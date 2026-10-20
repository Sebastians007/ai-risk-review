"""Authored readiness mappings, not legal conclusions. No network calls.

Catalog sources were reviewed on the date below. Review triggers deliberately
over-include: a local computer cannot establish statutory scope or exemptions.
"""
from datetime import date, timedelta

REVIEWED = '2026-10-19'
REVIEW_DAYS = 30


def question(key, label, group):
    return {'id': key, 'label': label, 'group': group}


QUESTIONS = [
    question('work_use', 'Do you use AI tools for work?', 'Your use'),
    question('policy', 'Have you agreed which AI uses are permitted?', 'Your use'),
    question('sensitive_data', 'Do work inputs include sensitive information?', 'Your use'),
    question('federal', 'Is this AI used by, or supplied under contract to, a U.S. federal agency?', 'Where requirements may apply'),
    question('employment', 'Does AI help hire, promote, assess or manage workers?', 'Where requirements may apply'),
    question('consequential', 'Does AI influence decisions about education, jobs, housing, credit, insurance, health care or public benefits?', 'Where requirements may apply'),
    question('health', 'Does this involve a HIPAA-regulated entity or protected health information?', 'Where requirements may apply'),
    question('consumer', 'Is AI offered to consumers, or are claims made about its capabilities?', 'Where requirements may apply'),
    question('colorado', 'Are Colorado residents or activities involved?', 'Where requirements may apply'),
    question('california', 'Are California residents or activities involved?', 'Where requirements may apply'),
    question('texas', 'Are Texas residents or activities involved?', 'Where requirements may apply'),
    question('nyc', 'Are New York City jobs or candidates involved?', 'Where requirements may apply'),
    question('ownership', 'Is there a named accountable owner for each AI use?', 'Evidence you can confirm'),
    question('use_cases', 'Are intended uses, affected people and data flows documented?', 'Evidence you can confirm'),
    question('vendor_review', 'Have vendor terms, retention, training use and permissions been reviewed?', 'Evidence you can confirm'),
    question('human_review', 'Are human review, escalation and override procedures documented?', 'Evidence you can confirm'),
    question('testing', 'Have accuracy, safety and misuse tests been recorded for the actual use?', 'Evidence you can confirm'),
    question('fairness', 'Have bias and accessibility evaluations been recorded for affected people?', 'Evidence you can confirm'),
    question('privacy_review', 'Has a privacy and sensitive-data assessment been recorded?', 'Evidence you can confirm'),
    question('monitoring', 'Are ongoing monitoring, incident response and rollback procedures recorded?', 'Evidence you can confirm'),
    question('training', 'Have relevant users received AI-use training?', 'Evidence you can confirm'),
]
CONTEXT_KEYS = frozenset(q['id'] for q in QUESTIONS)


def source(key, title, kind, url, trigger, scope, status, controls, provision):
    return dict(id=key, title=title, kind=kind, url=url, trigger=trigger, scope=scope,
                status=status, controls=controls, provision=provision, reviewed_at=REVIEWED)


SOURCES = [
    source('nist-rmf', 'NIST AI RMF 1.0', 'Voluntary framework',
           'https://airc.nist.gov/airmf-resources/airmf/5-sec-core/', (),
           'Optional cross-sector risk-management baseline; adoption may also be contractual.',
           'Published baseline; NIST states a revision is in progress.',
           [], 'GOVERN, MAP, MEASURE and MANAGE subcategories'),
    source('nist-genai', 'NIST AI 600-1: Generative AI Profile', 'Voluntary framework',
           'https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf', (),
           'Companion profile when the use involves generative AI; confirm the system type.',
           'Published July 2024; companion to AI RMF, not a certification.',
           ['use-cases', 'vendors', 'testing', 'privacy', 'monitoring'], 'Sections 2–3: GenAI risks and suggested actions (topic-level mapping)'),
    source('omb-25-21', 'OMB M-25-21: Federal use of AI', 'Federal agency policy',
           'https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf', ('federal',),
           'Federal agency AI use; contractors must examine agency instructions and contract terms.',
           'April 2025 memo; replaces M-24-10. Confirm agency scope, exceptions and current implementing policy.',
           ['inventory', 'ownership', 'use-cases', 'testing', 'human-review', 'monitoring'], 'AI governance and high-impact AI risk-management provisions (topic-level mapping)'),
    source('omb-25-22', 'OMB M-25-22: Federal AI acquisition', 'Federal agency policy',
           'https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf', ('federal',),
           'Federal AI acquisition; not a general private-business requirement.',
           'April 2025 memo; replaces M-24-18. Check procurement and contract-specific clauses.',
           ['vendors', 'use-cases', 'monitoring'], 'Acquisition, competition, interoperability and risk provisions (topic-level mapping)'),
    source('omb-26-04', 'OMB M-26-04: Unbiased AI principles', 'Federal agency policy',
           'https://www.whitehouse.gov/wp-content/uploads/2025/12/M-26-04-Increasing-Public-Trust-in-Artificial-Intelligence-Through-Unbiased-AI-Principles.pdf', ('federal',),
           'Covered federal procurement of large language models; examine exceptions and contract applicability.',
           'December 2025 memo; includes a two-year sunset unless OMB provides otherwise. Assess current status and other applicable federal AI instructions.',
           ['vendors', 'testing'], 'Contract requirements and Appendix A implementation guidance (topic-level mapping)'),
    source('ftc', 'FTC: AI consumer-protection enforcement', 'Existing law / agency guidance',
           'https://www.ftc.gov/industry/technology/artificial-intelligence', ('consumer',),
           'Consumer-facing AI and AI claims; FTC jurisdiction and other statutory limits require review.',
           'Existing consumer-protection law can apply to AI. The linked enforcement hub is not a standalone AI statute.',
           ['policy', 'testing', 'privacy', 'human-review'], 'Truthful claims, privacy and consumer harm (issue-level mapping)'),
    source('eeoc', 'Federal employment law: AI and the ADA', 'Existing law / agency guidance',
           'https://www.eeoc.gov/eeoc-disability-related-resources/artificial-intelligence-and-ada', ('employment',),
           'AI in employment; assess covered-entity thresholds, disability accommodation and other employment laws.',
           'Existing employment protections; this entry focuses on ADA resources, not all employment obligations.',
           ['fairness', 'human-review', 'testing'], 'AI assessment and disability / accommodation resources (issue-level mapping)'),
    source('hipaa', 'HIPAA: Cloud processing and business associates', 'Existing law / agency guidance',
           'https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html', ('health',),
           'HIPAA covered entities / business associates and ePHI processing; health-related data alone does not establish HIPAA scope.',
           'Existing HIPAA obligations; confirm entity, data, service role and any required BAA.',
           ['privacy', 'vendors', 'monitoring'], 'HHS cloud guidance, questions 1–2 (issue-level mapping)'),
    source('co-admt', 'Colorado SB26-189: ADMT', 'State law / upcoming duties',
           'https://www.leg.colorado.gov/bills/SB26-189', ('colorado', 'consequential'),
           'Covered developers / deployers and ADMT materially influencing consequential decisions involving Colorado.',
           'Enacted May 2026; repeals and reenacts earlier provisions. The legislative summary identifies duties starting January 1, 2027. Confirm signed text, rules and exemptions.',
           ['use-cases', 'vendors', 'human-review', 'monitoring'], 'Enacted-act summary: documentation, notice, human review and records (topic-level mapping)'),
    source('ca-admt', 'California CCPA: ADMT and risk-assessment regulations', 'State regulations / phased duties',
           'https://cppa.ca.gov/regulations/ccpa_updates.html', ('california',),
           'Covered CCPA businesses and regulated processing / ADMT; thresholds, exemptions and specific use are unresolved.',
           'Regulations effective January 1, 2026; ADMT Article 11 compliance starts January 1, 2027. Other deadlines vary, including phased cybersecurity audits. Confirm the relevant provision.',
           ['use-cases', 'privacy', 'human-review', 'testing'], 'Approved text Articles 9–11; ADMT §7200 and notice §7220 (topic-level mapping)'),
    source('tx-traiga', 'Texas HB149: Responsible AI Governance Act', 'State law',
           'https://capitol.texas.gov/billlookup/BillSummary.aspx?Bill=HB149&LegSess=89R', ('texas',),
           'AI development / deployment with Texas nexus; review entity, use, exceptions and specific disclosure triggers.',
           'Effective January 1, 2026. Different provisions apply to different actors and uses.',
           ['use-cases', 'fairness', 'human-review', 'privacy'], 'Enrolled-bill summary: prohibited uses and specified disclosures (topic-level mapping)'),
    source('nyc-aedt', 'NYC Local Law 144: Automated employment decision tools', 'Local law and rules',
           'https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page', ('nyc', 'employment'),
           'Covered employer / employment agency use of a defined AEDT; job nexus and tool definition need review.',
           'Enforcement began July 2023; annual independent bias audit, public information and notices for covered use.',
           ['fairness', 'human-review', 'monitoring'], 'DCWP law / rule overview and FAQ (topic-level mapping)'),
]

# These are authored evidence work packages, not the full framework or official
# equivalence assertions. Each has a concrete artifact and an acceptance check.
CONTROL_SPECS = [
    ('inventory', 'AI system inventory', 'GOVERN 1.6', None, 'AI program owner',
     'Reconcile discovered tools with browser services, APIs, plugins, other devices and business systems; name an owner and approval state for every AI use.',
     'An owner-reviewed inventory with product, version, use, users, data categories, vendor, connections, approval and review date.',
     'Sample actual work processes against the register; resolve unexplained tools and record coverage gaps.'),
    ('policy', 'Permitted use and exceptions', 'GOVERN 1.4', 'policy', 'Business owner',
     'Obtain approved AI-use rules, prohibited data / uses and an exception process.',
     'A dated approved policy, exception register and acknowledgement records.',
     'Check approval, current version and whether sampled users can follow the rules.'),
    ('ownership', 'Accountability', 'GOVERN 2.1', 'ownership', 'Executive sponsor',
     'Identify the accountable business owner, technical owner and escalation contact for each use.',
     'A responsibility register linked to each use case.',
     'Confirm named owners accept their responsibilities and can authorize a pause.'),
    ('use-cases', 'Purpose, affected people and data flows', 'MAP 1.1', 'use_cases', 'Use-case owner',
     'Document intended use, decisions influenced, affected people, deployment states, system role, inputs, outputs and destinations.',
     'A per-use-case description and data-flow diagram, including local and remote integrations.',
     'Walk through a real workflow with the owner; reconcile all data destinations and human decisions.'),
    ('vendors', 'Vendor and connection assurance', 'GOVERN 6.1', 'vendor_review', 'IT / procurement',
     'Review each vendor and MCP connection for purpose, owner, permissions, retention, model-training use, subprocessors and exit arrangements.',
     'A vendor review with contract / DPA / BAA where applicable and dated access-setting evidence.',
     'Compare reviewed terms and permissions with the actual account tier, configured server and allowed actions.'),
    ('human-review', 'Human oversight and recourse', 'GOVERN 3.2', 'human_review', 'Operations owner',
     'Identify decisions needing human checking, reviewers, authority to override, escalation and affected-person feedback routes.',
     'An oversight procedure and a sampled record of review / override / appeal.',
     'Run a tabletop case with incorrect output; demonstrate escalation and authorized override.'),
    ('testing', 'Accuracy, safety and misuse evaluation', 'MEASURE 2.3', 'testing', 'Technical / quality owner',
     'Obtain representative use-specific tests, expected results, failure limits and approval decisions; installation facts cannot establish model quality.',
     'A versioned evaluation set and results covering errors, unsafe use, prompt injection and sensitive-output handling as relevant.',
     'Reproduce selected tests on the approved system version and document failures and acceptance decisions.'),
    ('fairness', 'Fairness and accessibility evaluation', 'MEASURE 2.11', 'fairness', 'HR / domain / accessibility owner',
     'Assess affected groups, accessibility, selection effects and accommodations; determine whether an independent statutory audit is required.',
     'A population-appropriate evaluation and, where required, an independent audit and publication / notice records.',
     'Have qualified reviewers check methods, affected populations, limitations and required independence.'),
    ('privacy', 'Privacy and sensitive-data assessment', 'MEASURE 2.10', 'privacy_review', 'Privacy / security owner',
     'Establish lawful / permitted data use, minimization, retention, access, transfers and handling of sensitive or regulated information.',
     'A reviewed data assessment with account-setting evidence, retention decisions and required agreements.',
     'Trace a representative input through storage, model processing, logs and deletion; verify documented restrictions.'),
    ('security', 'AI service and integration security', 'MEASURE 2.7', None, 'IT / security owner',
     'Verify listener reachability, authentication, MCP permissions, approval boundaries and least privilege in a separately authorized review.',
     'A service / integration access review with tested access boundaries; local binding alone is insufficient.',
     'Validate intended access with the service owner, including remote-access and unauthorized-action tests in an approved environment.'),
    ('monitoring', 'Monitoring, incidents and shutdown', 'MANAGE 4.1', 'monitoring', 'Operations / security owner',
     'Define monitoring, incident reporting, periodic review, vendor-change review and how to pause / replace the system.',
     'A monitoring plan, incident runbook, review schedule and tested rollback / shutdown record.',
     'Exercise an incident scenario; confirm ownership, notification and safe fallback.'),
    ('training', 'User training', 'GOVERN 2.2', 'training', 'People / training owner',
     'Teach permitted use, data handling, checking outputs and reporting unexpected AI behavior.',
     'Role-specific training material and completion records.',
     'Sample user understanding with a realistic data-handling and output-checking scenario.'),
]


def build_crosswalk(observations, coverage, context, today=None):
    today = today or date.today()
    due = date.fromisoformat(REVIEWED) + timedelta(days=REVIEW_DAYS)
    sources = []
    for spec in SOURCES:
        s = dict(spec)
        answers = [context.get(key, 'unsure') for key in s.pop('trigger')]
        if not answers:
            applicability, reason = 'Optional baseline', 'Use as a voluntary readiness reference; confirm GenAI scope where relevant.'
        elif 'no' in answers:
            applicability, reason = 'Outside declared trigger', 'At least one screening answer was no; this is not a legal exemption or a final applicability decision.'
        elif all(a == 'yes' for a in answers):
            applicability, reason = 'Potentially relevant', 'Screening answers match a review trigger; statutory definitions, thresholds, roles, exceptions and dates still need qualified review.'
        else:
            applicability, reason = 'Needs context', 'Required screening answers are missing or unsure; do not infer non-applicability.'
        s.update(applicability=applicability, reason=reason)
        sources.append(s)
    controls = []
    for key, title, provision, answer, owner, needed, deliverable, verification in CONTROL_SPECS:
        kinds = {'inventory': {'installed', 'package', 'running', 'artifact', 'configuration', 'integration', 'listener'},
                 'use-cases': {'integration'}, 'vendors': {'integration'}, 'security': {'listener', 'integration'}}.get(key, set())
        related = [o for o in observations if o.get('kind') in kinds]
        claim = context.get(answer, 'unsure') if answer else 'unsure'
        status = 'Reported gap' if claim == 'no' else 'Reported; verify evidence' if claim == 'yes' else 'Partial local evidence' if related else 'Evidence needed'
        evidence = [f"{o.get('id', 'unassigned')}: {o['evidence']}" for o in related]
        if answer:
            evidence.append(f'User answer {answer}: {claim}. Self-reported; supporting evidence has not been verified.')
        if not related and not answer:
            evidence.append('No matching local evidence collected. This is not evidence that a control is absent.')
        mappings = [{'source_id': 'nist-rmf', 'provision': provision, 'relationship': 'Partial supporting evidence only'}]
        for s in sources:
            if key in s['controls']:
                mappings.append({'source_id': s['id'], 'provision': s['provision'], 'relationship': 'Authored topic association; not equivalent requirements'})
        controls.append(dict(id=key, title=title, status=status, owner=owner, evidence=evidence,
                             evidence_ids=[o['id'] for o in related if 'id' in o], needed=needed,
                             deliverable=deliverable, verification=verification, mappings=mappings))
    return {
        'catalog': {'id': 'us-readiness-2026-10-19', 'reviewed_at': REVIEWED, 'review_due': due.isoformat(),
                    'freshness': 'Review overdue' if today > due else 'Within scheduled review window',
                    'exhaustive': False,
                    'coverage': '12 selected U.S. framework / policy / legal-source entries; 12 authored evidence work packages. Not the complete NIST framework or a complete legal crosswalk.',
                    'excluded': 'Other state and local laws, education / FERPA, credit / ECOA / FCRA, insurance rules, children / COPPA, biometrics, medical-device rules, frontier-model rules, national-security uses, contracts and internal policies are not comprehensively mapped. International standards used in the U.S., including ISO/IEC 42001, are not mapped.',
                    'update_mode': 'Bundled offline snapshot. No live legal update check; review primary sources and implementing rules before reliance. A review window is not a guarantee sources remain current.',
                    'mapping_basis': 'Mappings are authored readiness aids, not official NIST equivalences, legal opinions, audits or compliance determinations.'},
        'sources': sources, 'controls': controls,
        'next_steps': ['Resolve missing jurisdiction, sector, system-role and use-case context.',
                       'Address reported gaps and observed technical review items with the relevant owners.',
                       'Gather each work package’s deliverable; have a qualified reviewer assess sufficiency and applicability.',
                       'Reconcile wider AI use and unmapped jurisdictions / sectors before treating this as an organizational assessment.'],
    }
