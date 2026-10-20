"""Standalone blue / white report. Evidence appears once, with local references."""
from html import escape


STYLE = """+:root{color-scheme:light}*{box-sizing:border-box}body{font:14px/1.75 'Segoe UI',Arial,sans-serif;background:#f3f7fd;color:#101449;margin:0}main{max-width:1060px;margin:30px auto;padding:32px;background:white;border-radius:16px}h1{font-size:36px;letter-spacing:-.035em;line-height:1.2;margin:0 0 10px}h2{font-size:23px;line-height:1.3;margin:0 0 15px}h3{font-size:17px;line-height:1.4;margin:0 0 10px}p{color:#33466f;max-width:80ch;overflow-wrap:anywhere}a{color:#064fc9;text-underline-offset:3px;overflow-wrap:anywhere}header{border-bottom:3px solid #0866ff;padding-bottom:25px;margin-bottom:25px}.brand{color:#0866ff;font-weight:800;font-size:15px;margin:0 0 18px}.hint{font-size:11px;color:#576b90}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.stat{padding:17px;background:#edf4ff;border-radius:10px}.stat strong{font-size:26px;display:block}.stat span{font-size:11px;color:#3a5783}.section{border-top:1px solid #dbe5f4;padding-top:26px;margin-top:30px}.notice{background:#eaf2ff;color:#254e8e;padding:15px 18px;border-radius:10px}.card{padding:18px 0;border-bottom:1px solid #dbe5f4}.badge{display:inline-block;background:#eaf2ff;color:#064fc9;font-size:10px;font-weight:700;padding:4px 8px;border-radius:4px;margin:0 5px 8px 0}summary{cursor:pointer;font-weight:700;padding:10px 0}details p,details li{font-size:12px}dl{margin:10px 0}dt{font-size:11px;font-weight:700;color:#064fc9;margin-top:13px}dd{margin:4px 0;color:#33466f;font-size:13px}.refs a{display:inline-block;font-size:11px;background:#eaf2ff;padding:2px 7px;margin:3px;border-radius:4px;text-decoration:none}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:11px}td,th{border-bottom:1px solid #dbe5f4;padding:12px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf4ff;color:#35547e}td:first-child{min-width:110px}blockquote{margin:12px 0;background:#f3f7fd;border-radius:8px;padding:15px;font-size:12px;overflow-wrap:anywhere}li{margin:9px 0}footer{margin-top:35px;border-top:1px solid #dbe5f4;padding-top:16px;font-size:11px;color:#576b90}:target{outline:2px solid #0866ff;outline-offset:3px}@media(max-width:650px){main{padding:24px 18px;margin:0;border-radius:0}h1{font-size:29px}.stats{grid-template-columns:1fr 1fr}}@media print{body{background:white}main{margin:0;padding:0;max-width:none}details{display:block}details>*{display:block!important}summary{list-style:none}a{color:#064fc9}h2,h3{break-after:avoid}tr,blockquote{break-inside:avoid}.stat{background:#edf4ff}}
"""


def render_report(r):
    from workspace import make_summary
    e = lambda value: escape(str(value), quote=True)
    cw = r['crosswalk']; sources = {s['id']: s for s in cw['sources']}
    summary = r.get('summary') or make_summary(r)
    def refs(ids):
        return '<div class="refs">' + ''.join(f'<a href="#{e(i)}">{e(i)}</a>' for i in ids) + '</div>'
    def dl(items):
        return '<dl>' + ''.join(f'<dt>{e(label)}</dt><dd>{e(value)}</dd>' for label,value in items) + '</dl>'
    page = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Risk Review — Evidence report</title><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'none\'; base-uri \'none\'"><style>{STYLE}</style></head><body><main>',
            '<header><p class="brand">AI Risk Review</p><h1>Your AI evidence overview.</h1>',
            f'<p class="hint">{e(r["created_at"])} · v{e(r["app_version"])} · {e(r.get("privacy_mode", "local-detail"))}</p><p>{e(r["scope"])}</p></header>']
    if r.get('demo'): page.append('<p class="notice"><strong>SAMPLE MODE:</strong> discovery records are illustrative. Any selected documents were still read locally.</p>')
    page.append(f'<p class="notice">{e(r.get("privacy_note", "Local report: optional connection labels, profile text and selected document excerpts may contain sensitive information. Review before sharing."))}</p>')
    p = r.get('profile', {})
    if p.get('name') or p.get('purpose') or p.get('states') or p.get('role', 'unsure') != 'unsure' or p.get('sector', 'unsure') != 'unsure':
        page.append('<section class="section"><h2>Use-case profile</h2>' + dl([('Name',p.get('name','')),('Purpose',p.get('purpose','')),('Role',p.get('role','unsure')),('Area',p.get('sector','unsure')),('Affected states',', '.join(p.get('states',[])))]) + '<p class="hint">User-supplied context, not independently verified.</p></section>')
    page.append('<div class="stats">')
    for value,label in [(summary['tools'],'Supported tools'),(summary['review_items'],'Items to review'),(summary['document_candidates'],'Document candidates'),(summary['evidence_needed'],'Work packages need evidence')]:
        page.append(f'<div class="stat"><strong>{value}</strong><span>{label}</span></div>')
    page.append('</div><p class="hint">Collection and review counts, not a security or compliance score.</p><section class="section"><h2>Priority next actions</h2><ol>')
    for action in summary['actions']: page.append(f'<li><strong>{e(action["title"])}</strong><br>{e(action["detail"])}</li>')
    page.append('</ol></section>')
    if r.get('comparison'):
        c=r['comparison']; page.append(f'<section class="section"><h2>Baseline comparison</h2><p>{len(c["new"])} new · {len(c["unchanged"])} matching finding IDs · {len(c["no_longer_observed"])} no longer observed.</p><p>No longer observed is not verified resolution; scope and access may have changed.</p></section>')
    page.append('<section class="section"><h2>Collection coverage</h2><ul>')
    for c in r['coverage']: page.append(f'<li><strong>{e(c["id"])}: {e(c["status"])}</strong> — {e(c["detail"])}</li>')
    page.append('</ul></section><section class="section"><h2>Tool inventory</h2><ul>')
    for item in r.get('inventory',[]): page.append(f'<li><strong>{e(item["service"])}</strong> — {e(", ".join(item["sources"]))}</li>')
    page.append('</ul><p class="hint">Presence does not establish actual use, approval or binary authenticity.</p></section><section class="section"><h2>Findings and next steps</h2>')
    for f in r['findings']:
        page.append(f'<div class="card"><h3>{e(f["title"])}</h3><span class="badge">{e(f["priority"])}</span><span class="badge">{e(f["basis"])}</span>')
        page.append(dl([('Why review',f['explanation']),('Unknowns',f['limitation']),('Next step',f['action']),('Verification',f['verification'])]))
        if f.get('evidence_ids'): page.append(refs(f['evidence_ids']))
        else: page.append(f'<p>{e(f["evidence"])}</p>')
        page.append('</div>')
    if not r['findings']: page.append('<p>No review items generated. Check coverage and remaining unknowns.</p>')
    page.append('</section><section class="section"><h2>Readiness crosswalk</h2><p class="hint">Authored evidence work packages. No package is independently verified or marked compliant. Topic associations are not equivalent legal requirements.</p>')
    for c in cw['controls']:
        page.append(f'<details class="card" open><summary>{e(c["title"])}</summary><span class="badge">{e(c["status"])}</span><p>Suggested owner: {e(c["owner"])}</p>')
        page.append(refs(c.get('evidence_ids',[])+c.get('document_evidence_ids',[])))
        for value in c['evidence']:
            if not value.startswith('obs-'): page.append(f'<p>{e(value)}</p>')
        page.append(dl([('Still needed',c['needed']),('Deliverable',c['deliverable']),('Verification',c['verification'])]))
        page.append('<p><strong>Mapped references</strong></p><ul>')
        for m in c['mappings']:
            s=sources[m['source_id']]
            page.append(f'<li><a href="{e(s["url"])}">{e(s["title"])}</a> · {e(m["provision"])} · {e(s["applicability"])}</li>')
        page.append('</ul></details>')
    page.append('</section><section class="section"><h2>Evidence collected</h2><p class="hint">Observation IDs are local to this report. Referenced facts are stored here once.</p><div class="table-wrap"><table><thead><tr><th>Reference</th><th>Tool / record</th><th>Evidence</th></tr></thead><tbody>')
    for o in r['observations']:
        label=f'<strong>{e(o["connection_label"])}</strong><br>' if o.get('connection_label') else ''
        page.append(f'<tr id="{e(o.get("id",""))}"><td>{e(o.get("id",""))}</td><td>{e(o["service"])}<br>{e(o["kind"])}</td><td>{label}{e(o["evidence"])}</td></tr>')
    page.append('</tbody></table></div></section><section class="section"><h2>Selected documents and candidate evidence</h2>')
    for doc in r.get('documents',[]):
        page.append(f'<div class="card"><h3>{e(doc["name"])}</h3><p>{e(doc["status"])} — {e(doc["detail"])}</p><p class="hint">SHA-256: {e(doc.get("sha256","not available"))}</p></div>')
    if not r.get('documents'): page.append('<p>No selected document details included.</p>')
    for item in r.get('document_evidence',[]):
        page.append(f'<div class="card" id="{e(item["id"])}"><h3>{e(item["document_name"])} · {e(item["locator"])}</h3><p class="hint">{e(item["id"])} · {e(item["control_id"])} · {e(item["basis"])}</p><blockquote>{e(item["excerpt"])}</blockquote></div>')
    page.append('<p class="hint">Keyword matches do not establish implementation, approval, effectiveness or compliance. Verify the source, surrounding text, dates and applicability.</p></section><section class="section"><h2>U.S. source coverage</h2>')
    cat=cw['catalog'];page.append(f'<p><strong>{e(cat["freshness"])}</strong> · reviewed {e(cat["reviewed_at"])} · due {e(cat["review_due"])}</p>')
    for key in ('coverage','mapping_basis','update_mode','excluded'): page.append(f'<p class="hint">{e(cat[key])}</p>')
    for s in sources.values(): page.append(f'<details class="card"><summary>{e(s["title"])} — {e(s["applicability"])}</summary><p>{e(s["kind"])} · {e(s["scope"])}</p><p>{e(s["status"])}</p><p>{e(s["reason"])}</p><a href="{e(s["url"])}">Primary source</a></details>')
    page.append('</section><section class="section"><h2>Limits of this review</h2><ul>')
    for value in r['limitations']: page.append(f'<li>{e(value)}</li>')
    page.append('</ul></section><footer>AI Risk Review · Local evidence, clear next steps · Development preview</footer></main></body></html>')
    return ''.join(page)
