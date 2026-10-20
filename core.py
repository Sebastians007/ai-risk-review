"""Evidence rules and portable reports. No inference, remote calls or telemetry."""
from datetime import datetime, timezone
from html import escape
import ipaddress
import json
from crosswalk import build_crosswalk

VERSION = '0.4.0'


def is_loopback(address):
    try:
        return ipaddress.ip_address(address.split('%')[0]).is_loopback
    except ValueError:
        return False


def analyze(observations, coverage, context):
    observations = [dict(o, id=f'obs-{i:03d}') for i, o in enumerate(observations, 1)]
    findings = []
    for obs in observations:
        if obs['kind'] == 'listener' and obs.get('confirmed') and not is_loopback(obs.get('address', '')):
            findings.append({
                'id': f"bind:{obs['service']}:{obs['port']}:{obs['address']}",
                'title': f"{obs['service']} listens beyond loopback",
                'priority': 'Review', 'basis': 'Observed', 'source': 'listeners',
                'evidence': obs['evidence'],
                'explanation': 'The listening address is not restricted to the local loopback interface.',
                'limitation': 'Reachability from another device, firewall rules, internet exposure and authentication were not tested.',
                'action': 'If remote access is unnecessary, ask the service owner to restrict the listening address to loopback. Otherwise review firewall restrictions and authentication. Do not change a shared service without its owner.',
                'verification': 'Run this check again and confirm the intended binding. Ask IT to validate required remote access separately.',
            })
        if obs['kind'] == 'integration' and obs.get('enabled_state') != 'explicitly disabled':
            findings.append({
                'id': f"mcp:{obs['service']}:{obs['name']}",
                'title': f"Review {obs.get('transport', 'configured')} connection in {obs['service']} ({obs.get('connection_label', obs.get('entry_index', '?'))})",
                'priority': 'Context needed', 'basis': 'Observed', 'source': 'integrations',
                'evidence': obs['evidence'],
                'explanation': 'An MCP connection is configured. These connections can extend an assistant’s capabilities.',
                'limitation': 'Configuration does not prove the connection is running, has broad permissions, or is unsafe. Command arguments, environment values, tokens and conversation contents are not included in this report.',
                'action': f"Open {obs.get('config_reference', 'the client MCP settings')} and locate entry {obs.get('entry_index', '?')} in the declared server table (file order, not sorted display order). Confirm its owner, purpose, allowed tools, data destinations and approval settings. Review command arguments locally; do not paste credentials into the report.",
                'verification': 'Record the owner and permission review. A rescan can confirm configuration presence, not that permissions are appropriate.',
            })
        if obs['kind'] == 'integration' and obs.get('enabled_state') != 'explicitly disabled' and (obs.get('url_credentials_present') or obs.get('url_scheme') == 'http'):
            findings.append({
                'id': f"mcp-transport:{obs['service']}:{obs['name']}",
                'title': f"Check connection transport settings in {obs['service']} ({obs.get('entry_index', '?')})",
                'priority': 'Review', 'basis': 'Observed', 'source': 'integrations',
                'evidence': obs['evidence'],
                'explanation': 'The configured URL uses HTTP or contains a user-info component. Review whether plaintext transport or embedded credentials are intended.',
                'limitation': 'HTTP may be local-only. A user-info component does not establish a valid credential. No endpoint, authentication or traffic was tested.',
                'action': 'With the connection owner, inspect the referenced entry locally. Use appropriate protected transport and a supported secret store where needed; rotate a credential only if exposure is established.',
                'verification': 'Confirm the intended endpoint and credential handling with the owner and repeat the settings check.',
            })
    if context.get('work_use') == 'yes' and context.get('policy') == 'no':
        findings.append({
            'id': 'policy-review', 'title': 'Document permitted work use of AI',
            'priority': 'Review', 'basis': 'Reported', 'source': 'context',
            'evidence': 'You reported work use of AI and no agreed rules for that use.',
            'explanation': 'People may make different decisions about information sharing and output verification.',
            'limitation': 'This comes from your answers. The app did not inspect business policies or establish a legal obligation.',
            'action': 'Agree which tools and data types are permitted, who approves exceptions and when outputs need human checking.',
            'verification': 'Keep the approved rules and confirm that relevant people received them.',
        })
    if context.get('work_use') == 'yes' and context.get('sensitive_data') == 'yes':
        findings.append({
            'id': 'data-review', 'title': 'Check the conditions for sensitive information',
            'priority': 'Review', 'basis': 'Reported', 'source': 'context',
            'evidence': 'You reported entering sensitive information into AI tools for work.',
            'explanation': 'The appropriate treatment depends on the product, account tier, settings, contracts and information involved.',
            'limitation': 'The app did not read your inputs or vendor contracts. It has not established that a disclosure or breach occurred.',
            'action': 'Have the responsible owner confirm permitted information, retention, training settings and contractual protections before further sensitive use.',
            'verification': 'Retain the approval decision and relevant settings evidence; obtain specialist advice for restricted data.',
        })
    # Deduplicate matching process/listener sources while retaining IPv4/IPv6 scope.
    findings = list({f['id']: f for f in findings}.values())
    for f in findings:
        f['evidence_ids'] = [o['id'] for o in observations if o['evidence'] == f['evidence']]
    inventory={}
    for o in observations:
        name={'Claude Desktop':'Claude'}.get(o['service'],o['service'])
        item=inventory.setdefault(name,{'service':name,'sources':[],'evidence':[]})
        if o['kind'] not in item['sources']:item['sources'].append(o['kind'])
        if o['evidence'] not in item['evidence']:item['evidence'].append(o['evidence'])
    return {
        'format': 'ai-risk-review', 'schema_version': 1, 'app_version': VERSION,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'scope': 'This Windows computer, current user and explicitly selected checks. Not an organization-wide assessment.',
        'observations': observations, 'inventory':sorted(inventory.values(),key=lambda item:item['service'].lower()), 'coverage': coverage, 'context': context,
        'findings': findings,
        'crosswalk': build_crosswalk(observations, coverage, context),
        'limitations': [
            'Installed software or configuration does not establish actual use, ownership, approval or sensitive data handling.',
            'Browser-only AI, private accounts, remote hosts, unsupported applications and other users may be outside visibility.',
            'No subnet scan, exploit, inference request or production change is performed.',
            'Findings are automated checkup results, not professional sign-off, compliance certification or insurance advice.',
            'No observed findings does not mean the computer or business is secure. Check the collection coverage.',
            'The bundled U.S. source catalog is selected and dated, not exhaustive or continuously updated. Crosswalks identify evidence work, not compliance.',
        ],
    }


def validate_baseline(value):
    if not isinstance(value, dict) or value.get('format') != 'ai-risk-review' or value.get('schema_version') != 1:
        raise ValueError('Choose a schema-version-1 JSON report exported by AI Risk Review.')
    findings = value.get('findings')
    if not isinstance(findings, list) or len(findings) > 2000:
        raise ValueError('The baseline has an invalid findings list.')
    clean = []
    for f in findings:
        if not isinstance(f, dict) or not isinstance(f.get('id'), str) or len(f['id']) > 500:
            raise ValueError('The baseline contains an invalid finding identifier.')
        clean.append({'id': f['id']})
    if type(value.get('demo',False)) is not bool:
        raise ValueError('Invalid baseline mode.')
    return {'format': 'ai-risk-review', 'schema_version': 1, 'findings': clean,'demo':value.get('demo',False)}


def compare(previous, current):
    old = {f['id'] for f in previous.get('findings', [])}
    new = {f['id'] for f in current.get('findings', [])}
    return {'new': sorted(new-old), 'unchanged': sorted(new & old), 'no_longer_observed': sorted(old-new)}


def html_report(report):
    from reporting import render_report
    return render_report(report)
