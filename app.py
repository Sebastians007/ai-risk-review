"""AI Risk Review: local browser launcher and token-protected loopback API."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import threading
import time
from urllib.parse import urlsplit
import webbrowser

from collectors import collect, extract_integrations
from core import VERSION, analyze, compare, html_report, validate_baseline
from crosswalk import CONTEXT_KEYS, QUESTIONS
from workspace import validate_workspace, parse_documents_isolated, apply_workspace, share_report, worker_main

WEB = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'web'


def demo_collect(options, include_names=False):
    observations=[];coverage=[]
    for id in ('installed','packages','running','listeners','integrations','locations'):
        selected=options.get('installed') if id=='packages' else options.get(id)
        coverage.append({'id':id,'status':'complete' if selected else 'skipped',
                         'detail':'Illustrative demo records. This computer was not inspected.'})
    if options.get('installed'):
        observations.extend([{'kind':'installed','service':name,'evidence':f'DEMO: {name} installed record.'} for name in ['Ollama','Claude','LM Studio']])
        observations.append({'kind':'package','service':'Claude','evidence':'DEMO: current-user Claude package record.'})
    if options.get('running'):
        observations.extend([{'kind':'running','service':name,'count':1,'evidence':f'DEMO: {name} running process, no listener required.'} for name in ['ChatGPT','Codex']])
    if options.get('listeners'):
        observations.append({'kind':'listener','service':'Ollama','confirmed':True,'port':11434,'address':'0.0.0.0','evidence':'DEMO: recognized Ollama process on TCP 0.0.0.0:11434.'})
    if options.get('integrations'):
        observations.extend(extract_integrations({'mcpServers':{'demo-example':{'command':'example-tool'}}},'Claude Desktop',include_names))
    return observations,coverage


class State:
    def __init__(self,demo):
        self.token=secrets.token_urlsafe(32)
        self.lock=threading.Lock()
        self.report=None
        self.running=False
        self.error=None
        self.demo=demo
        self.last_activity=time.monotonic()


def validate_request(body):
    if not isinstance(body,dict) or set(body)-{'options','context','baseline','workspace','include_names'}:
        raise ValueError('Invalid scan request.')
    options=body.get('options',{})
    if not isinstance(options,dict) or set(options)-{'installed','running','listeners','integrations','locations'}:
        raise ValueError('Choose supported collection options.')
    if any(type(v) is not bool for v in options.values()):
        raise ValueError('Collection options must be true or false.')
    if not any(options.values()): raise ValueError('Select at least one check.')
    context=body.get('context',{})
    if not isinstance(context,dict) or set(context)-CONTEXT_KEYS:
        raise ValueError('Invalid context answers.')
    if any(v not in ('yes','no','unsure') for v in context.values()):
        raise ValueError('Choose yes, no or unsure.')
    if type(body.get('include_names', False)) is not bool:
        raise ValueError('Connection-name choice must be true or false.')
    validate_workspace(body.get('workspace', {}))
    baseline=body.get('baseline')
    if baseline is not None: baseline=validate_baseline(baseline)
    return options,context,baseline


class Handler(BaseHTTPRequestHandler):
    server_version='AI-Risk-Review'
    sys_version=''

    def log_message(self,*args): pass  # Never log tokens, request data or evidence.

    def send(self,status,content,kind='application/json; charset=utf-8',attachment=None):
        if not isinstance(content,bytes):content=content.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(content)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Cross-Origin-Resource-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if attachment:self.send_header('Content-Disposition',f'attachment; filename="{attachment}"')
        self.end_headers()
        try:self.wfile.write(content)
        except (BrokenPipeError,ConnectionResetError):pass

    def error(self,status,message):self.send(status,json.dumps({'error':message}))

    def allowed(self,api=False):
        expected=f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host')!=expected:
            self.error(403,'Unrecognized local host.');return False
        origin=self.headers.get('Origin')
        if origin and origin!=f'http://{expected}':
            self.error(403,'Cross-origin requests are not permitted.');return False
        supplied=self.headers.get('X-Review-Token','')
        if api and (not supplied.isascii() or not secrets.compare_digest(supplied,self.server.state.token)):
            self.error(403,'Reopen the app using its launcher. This session is not authorized.');return False
        if api:self.server.state.last_activity=time.monotonic()
        return True

    def do_GET(self):
        path=urlsplit(self.path).path
        if not self.allowed(path.startswith('/api/')):return
        if path in ('/','/app.js','/theme.js','/style.css','/font.ttf'):
            filename={'/':'index.html','/app.js':'app.js','/theme.js':'theme.js','/style.css':'style.css','/font.ttf':'font.ttf'}[path]
            kind={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/theme.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8','/font.ttf':'font/ttf'}[path]
            try:self.send(200,(WEB/filename).read_bytes(),kind)
            except OSError:self.error(500,'The packaged interface is unavailable.')
        elif path=='/api/state':
            state=self.server.state
            with state.lock:
                self.send(200,json.dumps({'running':state.running,'error':state.error,'report':state.report,'demo':state.demo,'version':VERSION,'questions':QUESTIONS}))
        elif path in ('/api/export.json','/api/export.html','/api/share.json','/api/share.html'):
            with self.server.state.lock:report=self.server.state.report
            if not report:self.error(409,'Complete a checkup before exporting.');return
            if path.startswith('/api/share.'): report=share_report(report)
            if path.endswith('.json'):self.send(200,json.dumps(report,indent=2),attachment='AI-Risk-Review.json')
            else:self.send(200,html_report(report),'text/html; charset=utf-8','AI-Risk-Review.html')
        else:self.error(404,'Not found.')

    def do_POST(self):
        if not self.allowed(api=True):return
        if self.path=='/api/shutdown':
            self.send(200,json.dumps({'closed':True}))
            threading.Thread(target=self.server.shutdown,daemon=True).start();return
        if self.path!='/api/scan':self.error(404,'Not found.');return
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':
            self.error(415,'Send JSON.');return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=9*1024*1024:raise ValueError('Request must be between 1 byte and 9 MB.')
            self.connection.settimeout(5)
            body=json.loads(self.rfile.read(size))
            options,context,baseline=validate_request(body)
            profile, documents=validate_workspace(body.get('workspace', {}))
            include_names=body.get('include_names', False)
            if baseline is not None and baseline['demo']!=self.server.state.demo:
                raise ValueError('Sample and live reports cannot be compared.')
        except (ValueError,TypeError,OSError,RecursionError):
            self.error(400,'Invalid request. Check selected checks, profile answers, document limits and baseline format.');return
        state=self.server.state
        with state.lock:
            if state.running:self.error(409,'A checkup is already running.');return
            state.running=True;state.error=None;state.report=None
        def work():
            try:
                observations,coverage=(demo_collect if state.demo else collect)(options,include_names=include_names)
                report=apply_workspace(analyze(observations,coverage,context),profile,parse_documents_isolated(documents))
                report['demo']=state.demo
                if baseline:report['comparison']=compare(baseline,report)
                with state.lock:state.report=report
            except Exception:
                with state.lock:state.error='The checkup could not finish. No report was produced. Try again or change the selected checks.'
            finally:
                with state.lock:state.running=False
        threading.Thread(target=work,daemon=True).start()
        self.send(202,json.dumps({'started':True}))


def make_server(port=0,demo=False):
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    server.state=State(demo)
    return server


def main():
    if sys.stdout and hasattr(sys.stdout,'reconfigure'):
        sys.stdout.reconfigure(errors='replace')
    parser=argparse.ArgumentParser(description='AI Risk Review: a Windows-first local AI checkup.')
    parser.add_argument('command',nargs='?',choices=['scan'],help='Run the terminal checkup.')
    parser.add_argument('--version',action='version',version=VERSION)
    parser.add_argument('--no-browser',action='store_true',help='Print the private local address instead of opening a browser.')
    parser.add_argument('--demo',action='store_true',help='Use illustrative discovery records; explicitly selected documents are still parsed locally.')
    parser.add_argument('--port',type=int,default=0,help='Local port; defaults to an available ephemeral port.')
    parser.add_argument('--scan',action='store_true',help='Run selected local checks from the command line.')
    parser.add_argument('--integrations',action='store_true',help='Opt into selected MCP JSON and Codex TOML configuration checks.')
    parser.add_argument('--locations',action='store_true',help='Opt into presence checks of supported fixed directories, without reading their contents.')
    parser.add_argument('--output',type=Path,help='Write CLI JSON report to this new file.')
    parser.add_argument('--json',dest='json_report',type=Path,help='Write a new JSON report file.')
    parser.add_argument('--html',dest='html_report',type=Path,help='Write a new readable HTML report file.')
    parser.add_argument('--context',type=Path,help='Use optional yes/no/unsure context answers from a selected JSON file (scan only).')
    parser.add_argument('--profile',type=Path,help='Use one selected use-case profile JSON file (scan only).')
    parser.add_argument('--evidence',type=Path,action='append',default=[],help='Select a supporting document; repeat for up to six files (scan only).')
    parser.add_argument('--connection-names',action='store_true',help='Include supported connection labels locally; requires --integrations.')
    parser.add_argument('--share-safe',action='store_true',help='Exclude connection labels, profile text and document details from exported reports (scan only).')
    args=parser.parse_args()
    scanning=args.scan or args.command=='scan'
    if not scanning and (args.output or args.json_report or args.html_report or args.context or args.profile or args.evidence or args.connection_names or args.share_safe):
        parser.error('Use scan or --scan with report output options.')
    if args.output and args.json_report:parser.error('Choose --json or legacy --output, not both.')
    if scanning:
        json_path=args.json_report or args.output
        outputs=[p for p in [json_path,args.html_report] if p is not None]
        if len({str(p.resolve()).casefold() for p in outputs})!=len(outputs):
            parser.error('HTML and JSON outputs must use different files.')
        if any(p.exists() or not p.parent.is_dir() for p in outputs):
            parser.error('Output files must be new and their parent directories must already exist.')
        options={'installed':True,'running':True,'listeners':True,'integrations':args.integrations,'locations':args.locations}
        context={}
        if args.context:
            try:
                if args.context.stat().st_size > 65536:raise ValueError('Context is too large.')
                context=json.loads(args.context.read_text(encoding='utf-8-sig'))
                validate_request({'options':options,'context':context})
            except (OSError,ValueError,TypeError,RecursionError):
                parser.error('Context must be a JSON object of supported question keys and yes/no/unsure values, at most 64 KB. See examples/context-template.json.')
        profile={};documents=[]
        try:
            if args.profile:
                if args.profile.stat().st_size>65536:raise ValueError('Profile too large.')
                profile=json.loads(args.profile.read_text(encoding='utf-8-sig'))
            if len(args.evidence)>6:raise ValueError('Too many evidence files.')
            for selected in args.evidence:
                if selected.stat().st_size>1024*1024:raise ValueError('Evidence file too large.')
                documents.append({'name':selected.name,'data':base64.b64encode(selected.read_bytes()).decode('ascii')})
            profile,documents=validate_workspace({'profile':profile,'documents':documents})
        except (OSError,ValueError,TypeError,RecursionError):
            parser.error('Invalid profile or evidence selection. Use supported profile keys and up to 6 supported files, 1 MB each / 4 MB total.')
        if args.connection_names and not args.integrations:parser.error('--connection-names requires --integrations.')
        obs,coverage=(demo_collect if args.demo else collect)(options,include_names=args.connection_names)
        report=apply_workspace(analyze(obs,coverage,context),profile,parse_documents_isolated(documents));report['demo']=args.demo
        documents_incomplete=any(d['status'] not in ('read',) for d in report['documents'])
        if args.share_safe:report=share_report(report)
        text=json.dumps(report,indent=2)
        try:
            if json_path:
                with json_path.open('x',encoding='utf-8') as f:f.write(text)
            if args.html_report:
                with args.html_report.open('x',encoding='utf-8') as f:f.write(html_report(report))
        except OSError:parser.error('Could not create a report output. Check permissions and whether a file appeared during the scan.')
        if sys.stdout:
            if args.scan and not outputs:print(text)
            else:
                print(f'AI Risk Review {VERSION}'+(' — SAMPLE DATA' if args.demo else ' — Local checkup'))
                for c in coverage:print(f'  {c["id"]}: {c["status"]} — {c["detail"]}')
                print('\nObserved tool inventory:')
                for item in report['inventory']:print(f'  {item["service"]}: {", ".join(item["sources"])}')
                if not report['inventory']:print('  No supported tools observed; review coverage before drawing conclusions.')
                print(f'\n{len(report["findings"])} item(s) to review. No compliance or safety conclusion is implied.')
                for f in report['findings']:print(f'  {f["title"]}\n    Next step: {f["action"]}')
                cat=report['crosswalk']['catalog']
                print(f'\nU.S. readiness catalog: {cat["freshness"]}; reviewed {cat["reviewed_at"]}. Selected coverage, not exhaustive.')
                for c in report['crosswalk']['controls']:print(f'  {c["title"]}: {c["status"]} — suggested owner: {c["owner"]}')
                for p in outputs:print(f'Saved: {p}')
        return 2 if documents_incomplete or any(c['status'] in ('partial','unavailable') for c in coverage) else 0
    server=make_server(args.port,args.demo)
    url=f'http://127.0.0.1:{server.server_port}/#session={server.state.token}'
    if sys.stdout:print(f'AI Risk Review v{VERSION}\nPrivate session address (do not share): {url}',flush=True)
    if not args.no_browser:webbrowser.open(url)
    def expire():
        while True:
            time.sleep(15)
            if time.monotonic()-server.state.last_activity>1800:
                server.shutdown();return
    threading.Thread(target=expire,daemon=True).start()
    try:server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:pass
    finally:server.server_close()


if __name__=='__main__':raise SystemExit(worker_main() if sys.argv[1:]==['--document-worker'] else (main() or 0))
