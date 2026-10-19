"""Evidence rules and portable reports. No inference, remote calls or telemetry."""
from datetime import datetime, timezone
from html import escape
import ipaddress
import json

VERSION = '0.2.0'


def is_loopback(address):
    try:
        return ipaddress.ip_address(address.split('%')[0]).is_loopback
    except ValueError:
        return False


def analyze(observations, coverage, context):
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
        if obs['kind'] == 'integration':
            findings.append({
                'id': f"mcp:{obs['service']}:{obs['name']}",
                'title': f"Review a configured connection in {obs['service']}",
                'priority': 'Context needed', 'basis': 'Observed', 'source': 'integrations',
                'evidence': obs['evidence'],
                'explanation': 'An MCP connection is configured. These connections can extend an assistant’s capabilities.',
                'limitation': 'Configuration does not prove the connection is running, has broad permissions, or is unsafe. Command arguments, environment values, tokens and conversation contents are not included in this report.',
                'action': 'Confirm this connection is expected and identify its owner. Review the actual permissions and allowed actions in the client and server settings.',
                'verification': 'Record the owner and permission review. A rescan can confirm configuration presence, not that permissions are appropriate.',
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
        'limitations': [
            'Installed software or configuration does not establish actual use, ownership, approval or sensitive data handling.',
            'Browser-only AI, private accounts, remote hosts, unsupported applications and other users may be outside visibility.',
            'No subnet scan, exploit, inference request or production change is performed.',
            'Findings are automated checkup results, not professional sign-off, compliance certification or insurance advice.',
            'No observed findings does not mean the computer or business is secure. Check the collection coverage.',
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
    def esc(v): return escape(str(v), quote=True)
    rows = ''.join(f"<tr><td>{esc(o.get('service',''))}</td><td>{esc(o['kind'])}</td><td>{esc(o.get('evidence',''))}</td></tr>" for o in report['observations'])
    inventory=''.join(f'<li><strong>{esc(item["service"])}</strong> — {esc(", ".join(item["sources"]))}</li>' for item in report.get('inventory',[]))
    coverage = ''.join(f"<li><strong>{esc(c['id'])}: {esc(c['status'])}</strong> — {esc(c['detail'])}</li>" for c in report['coverage'])
    findings = ''.join(f"""<section><h2>{esc(f['title'])}</h2><p><strong>{esc(f['priority'])} · {esc(f['basis'])}</strong></p>
    <p><strong>Evidence:</strong> {esc(f['evidence'])}</p><p>{esc(f['explanation'])}</p>
    <p><strong>Unknowns:</strong> {esc(f['limitation'])}</p><p><strong>Next step:</strong> {esc(f['action'])}</p>
    <p><strong>Verification:</strong> {esc(f['verification'])}</p></section>""" for f in report['findings'])
    if not findings:
        findings = '<p>No findings were generated from the selected checks and answers. Review coverage and limitations before drawing conclusions.</p>'
    changes = ''
    if 'comparison' in report:
        c = report['comparison']
        changes = f"<section><h2>Compared with your imported baseline</h2><p>{len(c['new'])} new · {len(c['unchanged'])} unchanged · {len(c['no_longer_observed'])} no longer observed.</p><p>No longer observed is not verified resolution. Collection scope or access may have changed.</p></section>"
    limitations = ''.join(f'<li>{esc(v)}</li>' for v in report['limitations'])
    demo_note='<p><strong>SAMPLE MODE: illustrative records only. This computer was not inspected.</strong></p>' if report.get('demo') else ''
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Risk Review — Local checkup</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'">
    <style>body{{font:16px/1.7 'Segoe UI',Arial,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;color:#182b34}}h1,h2{{font-family:Georgia,serif;line-height:1.3}}h1{{font-size:38px}}h2{{font-size:25px}}section{{border-top:1px solid #d5dfdf;margin-top:32px;padding-top:20px}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{text-align:left;vertical-align:top;border:1px solid #d5dfdf;padding:12px;overflow-wrap:anywhere}}th{{background:#edf3f2}}li{{margin:10px 0}}@media print{{body{{margin:0}}h2{{break-after:avoid}}tr{{break-inside:avoid}}}}</style></head><body>
    <h1>AI Risk Review</h1>{demo_note}<p>Local checkup · {esc(report['created_at'])} · v{esc(report['app_version'])}</p><p>{esc(report['scope'])}</p>
    <section><h2>Collection coverage</h2><ul>{coverage}</ul></section>
    <section><h2>Tool inventory</h2><ul>{inventory or '<li>No supported tools observed. Review coverage before drawing conclusions.</li>'}</ul><p>Multiple sources are combined by supported tool name. Presence does not establish actual use, approval or binary authenticity.</p></section>
    <section><h2>Evidence collected</h2><table><thead><tr><th>Tool</th><th>Record type</th><th>Evidence</th></tr></thead><tbody>{rows or '<tr><td colspan="3">No supported items observed. This does not establish absence.</td></tr>'}</tbody></table></section>
    {changes}<section><h2>Findings and next steps</h2></section>{findings}
    <section><h2>Limits of this checkup</h2><ul>{limitations}</ul></section>
    <section><h2>Guidance references</h2><ul><li><a href="https://www.nist.gov/itl/ai-risk-management-framework">NIST AI Risk Management Framework</a></li><li><a href="https://docs.ollama.com/faq">Ollama configuration and network binding</a></li><li><a href="https://modelcontextprotocol.io/docs/learn/server-concepts">MCP server concepts</a></li></ul><p>The rules are authored recommendations. These sources do not certify the results.</p></section></body></html>"""
