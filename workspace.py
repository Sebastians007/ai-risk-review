"""Explicit, bounded local evidence inputs. Document matches are never proof."""
import base64
import binascii
import copy
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from xml.etree import ElementTree as ET

MAX_FILE = 1024 * 1024
MAX_TOTAL = 4 * MAX_FILE
STATES = frozenset('AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC'.split())
ROLES = ('unsure', 'user', 'deployer', 'developer', 'both')
SECTORS = ('unsure', 'general', 'employment', 'health', 'finance', 'education', 'government')


def text_value(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError('Text exceeds the supported limit.')
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value).strip()


def validate_workspace(value):
    if not isinstance(value, dict) or set(value) - {'profile', 'documents'}:
        raise ValueError('Unsupported workspace fields.')
    profile = value.get('profile', {})
    if not isinstance(profile, dict) or set(profile) - {'name', 'purpose', 'role', 'sector', 'states'}:
        raise ValueError('Unsupported profile fields.')
    clean = {'name': text_value(profile.get('name', ''), 120), 'purpose': text_value(profile.get('purpose', ''), 1000),
             'role': profile.get('role', 'unsure'), 'sector': profile.get('sector', 'unsure')}
    if clean['role'] not in ROLES or clean['sector'] not in SECTORS:
        raise ValueError('Choose a supported role and sector.')
    states = profile.get('states', [])
    if not isinstance(states, list) or len(states) > 51 or any(not isinstance(s, str) or s not in STATES for s in states):
        raise ValueError('Choose supported U.S. state codes.')
    clean['states'] = sorted(set(states))
    docs = value.get('documents', [])
    if not isinstance(docs, list) or len(docs) > 6:
        raise ValueError('Choose at most six evidence files.')
    total = 0
    for item in docs:
        raw, _ = decode_document(item)
        total += len(raw)
    if total > MAX_TOTAL:
        raise ValueError('Selected files must total at most 4 MB.')
    return clean, docs


def decode_document(item):
    if not isinstance(item, dict) or set(item) != {'name', 'data'}:
        raise ValueError('A document must have a name and base64 data.')
    name = text_value(item['name'], 160)
    if not name or '/' in name or '\\' in name or ':' in name:
        raise ValueError('Use a filename without a directory.')
    suffix = Path(name).suffix.lower()
    if suffix not in ('.txt', '.md', '.html', '.htm', '.docx', '.pdf'):
        raise ValueError('Choose TXT, Markdown, HTML, DOCX or text-based PDF.')
    if not isinstance(item['data'], str) or len(item['data']) > (MAX_FILE + 2) // 3 * 4:
        raise ValueError('Each file must be at most 1 MB.')
    try:
        raw = base64.b64decode(item['data'], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('Invalid file data.') from None
    if not raw or len(raw) > MAX_FILE:
        raise ValueError('Each file must contain 1 byte to 1 MB.')
    return raw, name


class DocumentHTML(HTMLParser):
    def __init__(self):
        super().__init__(); self.ignore = 0; self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'noscript', 'template'): self.ignore += 1
        if not self.ignore and tag in ('p', 'div', 'li', 'h1', 'h2', 'h3', 'h4', 'br', 'tr'): self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript', 'template') and self.ignore: self.ignore -= 1
        if not self.ignore and tag in ('p', 'li', 'h1', 'h2', 'h3', 'h4', 'tr'): self.parts.append('\n')
    def handle_data(self, data):
        if not self.ignore: self.parts.append(data)


def parse_document(item):
    raw, name = decode_document(item)
    suffix = Path(name).suffix.lower()
    segments = []; truncated = False
    def add(locator, value):
        nonlocal truncated
        value = re.sub(r'\s+', ' ', value).strip()
        if value:
            if len(segments) >= 1000 or sum(len(s['text']) for s in segments) + len(value) > 160000:
                truncated = True; return
            segments.append({'locator': locator, 'text': value[:6000]})
            if len(value) > 6000: truncated = True
    if suffix == '.docx':
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info = archive.getinfo('word/document.xml')
            if info.file_size > 2 * MAX_FILE or info.flag_bits & 1:
                raise ValueError('DOCX content is too large or encrypted.')
            xml = archive.read(info)
            if b'<!DOCTYPE' in xml.upper() or b'<!ENTITY' in xml.upper():
                raise ValueError('Unsupported XML declarations.')
            root = ET.fromstring(xml)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            for i, paragraph in enumerate(root.findall('.//w:p', ns), 1):
                add(f'paragraph {i}', ''.join(n.text or '' for n in paragraph.findall('.//w:t', ns)))
    elif suffix == '.pdf':
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted: raise ValueError('Encrypted PDFs are unsupported.')
        count = len(reader.pages)
        if count > 100: truncated = True
        for i in range(min(count, 100)):
            add(f'page {i+1}', reader.pages[i].extract_text() or '')
    else:
        text = raw.decode('utf-8-sig')
        if '\x00' in text: raise ValueError('Unsupported binary content.')
        if suffix in ('.html', '.htm'):
            parser = DocumentHTML(); parser.feed(text)
            for i, line in enumerate(''.join(parser.parts).splitlines(), 1): add(f'text block {i}', line)
        else:
            for i, line in enumerate(text.splitlines(), 1): add(f'line {i}', line)
    digest = hashlib.sha256(raw).hexdigest()
    return {'id': 'doc-' + digest[:16], 'name': name, 'sha256': digest, 'bytes': len(raw),
            'status': 'partial' if truncated else 'read' if segments else 'no extractable text',
            'detail': 'Bounded text extraction; excerpts require review. No OCR, embedded objects or remote resources are processed.',
            'segments': segments}


def parse_documents_isolated(items):
    """No shell or file paths. Frozen builds relaunch the CLI-safe worker mode."""
    output = []
    for i, item in enumerate(items, 1):
        if getattr(sys, 'frozen', False):
            executable = Path(sys.executable)
            if executable.name.lower() == 'ai-risk-review.exe':
                executable = executable.with_name('AI-Risk-Review-CLI.exe')
            args = [str(executable), '--document-worker']
        else:
            args = [sys.executable, str(Path(__file__).with_name('app.py')), '--document-worker']
        proc = None
        try:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            data, _ = proc.communicate(json.dumps(item).encode('utf-8'), timeout=12)
            if proc.returncode or len(data) > 1200000: raise ValueError('Document parse failed.')
            result = json.loads(data)
            if not isinstance(result, dict) or result.get('status') == 'error': raise ValueError('Document parse failed.')
            output.append(result)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            if proc is not None and proc.poll() is None:
                if sys.platform == 'win32':
                    subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), timeout=5)
                else: proc.kill()
                proc.communicate()
            output.append({'id': f'doc-unavailable-{i}', 'name': item['name'], 'status': 'unavailable', 'detail': 'Could not safely extract text within the supported format, size and time limits. No content conclusion is implied.', 'segments': []})
    return output


KEYWORDS = {
    'inventory': ('ai inventory', 'system register', 'tool inventory'),
    'policy': ('ai policy', 'approved tools', 'acceptable use', 'permitted use'),
    'ownership': ('accountable owner', 'responsibility', 'ai owner'),
    'use-cases': ('use case', 'data flow', 'intended use'),
    'vendors': ('retention', 'subprocessor', 'vendor', 'data processing agreement', 'business associate'),
    'human-review': ('human review', 'override', 'appeal', 'escalation'),
    'testing': ('evaluation', 'accuracy test', 'test results', 'prompt injection'),
    'fairness': ('bias audit', 'fairness', 'accessibility', 'accommodation'),
    'privacy': ('personal data', 'sensitive data', 'privacy assessment', 'data minimization'),
    'security': ('least privilege', 'access control', 'authentication', 'permission'),
    'monitoring': ('incident response', 'monitoring', 'rollback', 'shutdown'),
    'training': ('training completion', 'ai training', 'user training'),
}


def document_candidates(documents):
    result = []
    for doc in documents:
        for control, keywords in KEYWORDS.items():
            hits = 0
            for segment in doc.get('segments', []):
                text = segment['text']; lowered = text.lower()
                match = next((word for word in keywords if word in lowered), None)
                if not match: continue
                start = max(0, lowered.index(match) - 100)
                result.append({'id': f'evidence-{len(result)+1:03d}', 'document_id': doc['id'],
                               'document_name': doc['name'], 'control_id': control, 'locator': segment['locator'],
                               'excerpt': text[start:start+450], 'match': match,
                               'basis': 'Keyword candidate; relevance and sufficiency unverified'})
                hits += 1
                if hits == 2: break
    return result


def apply_workspace(report, profile, documents):
    from crosswalk import build_crosswalk
    context = dict(report['context'])
    # Explicit profile choices add positive hints only. No legal exemption is inferred.
    sector_key = {'employment': 'employment'}.get(profile.get('sector'))
    # Health care alone does not establish HIPAA / PHI; government is not necessarily federal.
    if sector_key and context.get(sector_key, 'unsure') == 'unsure': context[sector_key] = 'yes'
    for state, key in [('CA', 'california'), ('CO', 'colorado'), ('TX', 'texas')]:
        if state in profile.get('states', []) and context.get(key, 'unsure') == 'unsure': context[key] = 'yes'
    report['context'] = context
    report['profile'] = profile
    cw = build_crosswalk(report['observations'], report['coverage'], context)
    evidence = document_candidates(documents)
    for control in cw['controls']:
        control['document_evidence_ids'] = [e['id'] for e in evidence if e['control_id'] == control['id']]
        if control['document_evidence_ids'] and control['status'] != 'Reported gap':
            control['status'] = 'Document candidate; review needed'
        # Long local evidence is stored once in the appendix, not repeated.
        control['evidence'] = [e for e in control['evidence'] if not e.startswith('obs-')]
    report['crosswalk'] = cw
    report['documents'] = [{k: v for k, v in d.items() if k != 'segments'} for d in documents]
    report['document_evidence'] = evidence
    report['privacy_mode'] = 'local-detail'
    report['summary'] = make_summary(report)
    return report


def make_summary(report):
    controls = report['crosswalk']['controls']; sources = report['crosswalk']['sources']
    actions = []
    unresolved = sum(s['applicability'] == 'Needs context' for s in sources)
    for finding in sorted(report['findings'], key=lambda f: f['priority'] != 'Review')[:3]:
        actions.append({'title': finding['title'], 'detail': finding['action'], 'target': 'findings'})
    incomplete = sum(d['status'] != 'read' for d in report.get('documents', []))
    if incomplete:
        actions.append({'title': 'Resolve incomplete document extraction', 'detail': f'{incomplete} selected document(s) were partial, unavailable or had no extractable text. Review document status and supply a readable, supported version where needed.', 'target': 'evidence'})
    if unresolved:
        actions.append({'title': 'Resolve applicability questions', 'detail': f'{unresolved} source entries still need context. Confirm affected jurisdictions, sector, system role and use.', 'target': 'sources'})
    for c in sorted(controls, key=lambda c: c['status'] != 'Reported gap'):
        if len(actions) >= 5: break
        if c['id'] == 'policy' and any(f['id'] == 'policy-review' for f in report['findings']): continue
        if c['status'] == 'Reported gap' or (c['status'] == 'Evidence needed' and c['id'] in ('policy', 'ownership')):
            actions.append({'title': c['title'], 'detail': c['needed'], 'target': 'crosswalk'})
    return {'tools': len(report['inventory']), 'observations': len(report['observations']),
            'review_items': len(report['findings']), 'document_candidates': len(report.get('document_evidence', [])),
            'evidence_needed': sum(c['status'] == 'Evidence needed' for c in controls),
            'reported_gaps': sum(c['status'] == 'Reported gap' for c in controls),
            'sources_needing_context': unresolved, 'documents_incomplete': incomplete, 'actions': actions[:5],
            'note': 'These are collection and review counts, not a security or compliance score.'}


def share_report(report):
    from core import analyze
    observations = copy.deepcopy(report['observations'])
    for o in observations:
        o.pop('connection_label', None)
    clean = analyze(observations, copy.deepcopy(report['coverage']), copy.deepcopy(report['context']))
    clean = apply_workspace(clean, {}, [])
    clean['created_at'] = report['created_at']
    clean['demo'] = report.get('demo', False)
    if 'comparison' in report: clean['comparison'] = copy.deepcopy(report['comparison'])
    clean['privacy_mode'] = 'share-safe'
    clean['privacy_note'] = 'Connection labels, use-case profile text and document names / excerpts excluded. Tool, configuration, context answers, pseudonymous identifiers and security observations remain; review before sharing.'
    return clean


def worker_main():
    try:
        limit_worker_memory()
        raw = sys.stdin.buffer.read(1500001)
        if len(raw) > 1500000: raise ValueError('Worker input too large.')
        result = parse_document(json.loads(raw))
    except Exception:
        result = {'status': 'error'}
    sys.stdout.buffer.write(json.dumps(result).encode('utf-8'))
    return 0


def limit_worker_memory():
    """Apply a hard per-parser process budget before parsing compressed inputs."""
    if sys.platform != 'win32':
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
        return
    import ctypes
    from ctypes import wintypes
    class BasicLimits(ctypes.Structure):
        _fields_ = [('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),
                    ('flags',wintypes.DWORD),('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),
                    ('active',wintypes.DWORD),('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(key,ctypes.c_ulonglong) for key in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic',BasicLimits),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
    kernel=ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];kernel.CreateJobObjectW.restype=wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD];kernel.SetInformationJobObject.restype=wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE];kernel.AssignProcessToJobObject.restype=wintypes.BOOL
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.CreateJobObjectW(None,None)
    limits=ExtendedLimits();limits.basic.flags=0x100;limits.process_memory=512*1024*1024
    if not handle or not kernel.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle,kernel.GetCurrentProcess()):
        if handle:kernel.CloseHandle(handle)
        raise RuntimeError('Parser memory boundary unavailable.')
    # Keep the job handle open for this short-lived worker's lifetime.
