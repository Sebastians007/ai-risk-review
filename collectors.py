"""Bounded, read-only Windows collectors. No cloud calls or credential extraction."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

# Deliberately narrow signatures, not arbitrary substrings such as 'AI'.
APPS = {
    'ollama': 'Ollama', 'lm studio': 'LM Studio', 'chatgpt': 'ChatGPT',
    'claude': 'Claude', 'cursor': 'Cursor', 'windsurf': 'Windsurf',
    'gpt4all': 'GPT4All', 'anythingllm': 'AnythingLLM', 'cherry studio': 'Cherry Studio',
    'jan': 'Jan', 'codex':'Codex',
}
PROCESSES = {'ollama':'Ollama','ollama app':'Ollama','lm studio':'LM Studio',
             'claude':'Claude','chatgpt':'ChatGPT','cursor':'Cursor','windsurf':'Windsurf',
             'gpt4all':'GPT4All','anythingllm':'AnythingLLM','codex':'Codex'}
PACKAGES = {'claude':'Claude','openai.codex':'Codex','openai.chatgpt-desktop':'ChatGPT',
            'openai.chatgpt':'ChatGPT'}


def rows(value, fields):
    if isinstance(value,dict): value=[value]
    if not isinstance(value,list): raise ValueError('Expected a Windows record list.')
    for row in value:
        if not isinstance(row,dict) or any(field not in row for field in fields):
            raise ValueError('Windows record fields were unavailable.')
    return value


def powershell(command):
    executable=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
    script='$ErrorActionPreference="Stop"; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); '+command
    output=run_windows([str(executable),'-NoProfile','-NonInteractive','-Command',script])
    return json.loads(output.lstrip('\ufeff'))


def parse_packages(value):
    result=[]
    for item in rows(value,('Name','Version')):
        label=PACKAGES.get(str(item['Name']).lower())
        if label:
            version = str(item['Version'])
            version = version if re.fullmatch(r'\d[\d.\-]{0,59}', version) else 'not extracted'
            result.append({'kind':'package','service':label,
                'version':version,
                'evidence':f'Recognized current-user Windows package name: {item["Name"]}; version {version}. Installation record only; actual use and approval are unknown.'})
    return result


def packages():
    value=powershell('ConvertTo-Json -InputObject @(Get-AppxPackage | Select-Object Name,Version) -Compress')
    obs=parse_packages(value)
    return obs,{'id':'packages','status':'complete','detail':f'Checked current-user Windows package records; {len(obs)} supported matches. Other users, provisioned-but-unregistered packages and unsupported identities are outside coverage.'}


def parse_processes(value):
    counts={}
    for item in rows(value,('Id','ProcessName')):
        label=PROCESSES.get(str(item['ProcessName']).lower())
        if label: counts[label]=counts.get(label,0)+1
    return [{'kind':'running','service':label,'count':count,
             'evidence':f'Recognized running process name: {label} ({count} process(es)). No listening port is required. Binary authenticity, activity and approval were not verified.'}
            for label,count in sorted(counts.items())]


def running():
    value=powershell('ConvertTo-Json -InputObject @(Get-Process | Select-Object Id,ProcessName) -Compress')
    obs=parse_processes(value)
    return obs,{'id':'running','status':'complete','detail':f'Checked visible process names independently of network listeners; {len(obs)} supported tools observed. No command lines, environment values or executable paths were collected. Names are identity hints.'}


def clean_label(value):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(value))[:100]


def match_app(name):
    name = name.strip().lower()
    for signature, label in APPS.items():
        if name == signature or re.fullmatch(re.escape(signature)+r'\s+v?\d[\d.\- a-z()]*', name):
            return label
    return None


def installed_apps():
    import winreg
    observations, succeeded, failed = [], 0, 0
    locations = [(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Uninstall', 0),
                 (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Uninstall', winreg.KEY_WOW64_64KEY),
                 (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Uninstall', winreg.KEY_WOW64_32KEY)]
    for hive, path, view in locations:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as parent:
                succeeded += 1
                for i in range(winreg.QueryInfoKey(parent)[0]):
                    try:
                        key_name = winreg.EnumKey(parent, i)
                        with winreg.OpenKey(parent, key_name) as app:
                            name = winreg.QueryValueEx(app, 'DisplayName')[0]
                            label = match_app(name) if isinstance(name,str) else None
                            if label:
                                observations.append({'kind':'installed','service':label,
                                    'evidence':f'Recognized Windows uninstall record: {label}. Actual use and approval are unknown.'})
                    except FileNotFoundError:
                        continue
                    except OSError:
                        failed += 1
        except FileNotFoundError:
            continue
        except OSError:
            failed += 1
    observations = list({o['service']:o for o in observations}.values())
    status = 'complete' if succeeded and not failed else 'partial' if succeeded else 'unavailable'
    return observations, {'id':'installed','status':status,'detail':f'Checked {succeeded} uninstall registry locations; {failed} records or locations could not be read. Does not include all Store apps, portable tools or browser-only use.'}


def run_windows(args):
    # No shell expansion, dynamic commands or visible console window.
    result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                            errors='replace', timeout=18, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode != 0:
        raise RuntimeError('The Windows collection command did not complete successfully.')
    return result.stdout


def parse_listeners(text, names):
    observations = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0].upper() != 'TCP' or fields[3].upper() != 'LISTENING':
            continue
        try:
            endpoint, pid = fields[1], int(fields[4])
            address, port = endpoint.rsplit(':', 1)
            address, port = address.strip('[]'), int(port)
        except (ValueError, IndexError):
            continue
        label = PROCESSES.get(names.get(pid,'').lower())
        if label:
            observations.append({'kind':'listener','service':label,'confirmed':True,'port':port,'address':address,
                                 'evidence':f'Recognized process {label} (PID {pid}) listens on TCP {address}:{port}. Service behavior was not tested.'})
    return observations


def listeners():
    # Process identity comes from Windows, not from a generic port number.
    values=rows(powershell('ConvertTo-Json -InputObject @(Get-Process | Select-Object Id,ProcessName) -Compress'),('Id','ProcessName'))
    names = {int(x['Id']):str(x['ProcessName']) for x in values}
    executable=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/netstat.exe'
    output = run_windows([str(executable),'-ano','-p','tcp'])
    if 'TCP' not in output.upper():
        return [], {'id':'listeners','status':'unavailable','detail':'Windows returned no recognizable TCP records. Local listeners could not be assessed.'}
    # Non-English netstat output uses localized state labels. Fail visibly rather than declaring no findings.
    if 'LISTENING' not in output.upper():
        return [], {'id':'listeners','status':'unavailable','detail':'No supported LISTENING records were returned. This preview supports English netstat output; listeners were not assessed.'}
    obs = parse_listeners(output, names)
    return obs, {'id':'listeners','status':'complete','detail':'Matched current TCP listeners to supported running process names. No network probes were sent. Firewall reachability, authentication and remote hosts were not tested.'}


def extract_integrations(data, app):
    if not isinstance(data,dict): raise ValueError('Expected a JSON object.')
    servers = data.get('mcpServers', data.get('servers', {}))
    if not isinstance(servers,dict): raise ValueError('Unrecognized MCP configuration structure.')
    if len(servers)>200: raise ValueError('Too many entries for a bounded configuration check.')
    result=[]
    for index, (name, config) in enumerate(servers.items(), 1):
        if not isinstance(config,dict): continue
        # Extract allowlisted facts only. Never export arbitrary strings from config.
        connection = 'local command' if 'command' in config else 'remote URL' if 'url' in config else 'unspecified'
        stable_id=hashlib.sha256(str(name).encode('utf-8')).hexdigest()[:20]
        # Only interpret settings whose semantics are known for this client.
        # For example, VS Code keeps enable/disable state outside this JSON.
        state='explicitly disabled' if app == 'Codex' and config.get('enabled') is False else 'activation state not verified'
        from urllib.parse import urlsplit
        scheme='not configured'; credentials=False
        if isinstance(config.get('url'),str):
            try:
                parsed=urlsplit(config['url'])
                scheme=parsed.scheme.lower() if parsed.scheme.lower() in ('http','https') else 'other / unspecified'
                credentials=parsed.username is not None or parsed.password is not None
            except ValueError:scheme='unparseable'
        auth=any(key in config for key in ('headers','http_headers','env_http_headers','bearer_token_env_var','oauth'))
        allowed=config.get('enabled_tools');blocked=config.get('disabled_tools')
        allowed_count=len(allowed) if isinstance(allowed,list) else None
        blocked_count=len(blocked) if isinstance(blocked,list) else None
        reference={'Claude Desktop':'%APPDATA%/Claude/claude_desktop_config.json → mcpServers',
                   'Cursor':'%USERPROFILE%/.cursor/mcp.json → mcpServers',
                   'VS Code':'%APPDATA%/Code/User/mcp.json → servers',
                   'Windsurf':'%USERPROFILE%/.codeium/windsurf/mcp_config.json → mcpServers',
                   'Codex':'CODEX_HOME/config.toml (default %USERPROFILE%/.codex/config.toml) → mcp_servers'}.get(app,'client MCP settings')
        result.append({'kind':'integration','service':app,'name':f'connection-{stable_id}',
                       'entry_index':index,'transport':connection,'enabled_state':state,
                       'config_reference':reference,'url_scheme':scheme,'url_credentials_present':credentials,
                       'auth_material_configured':auth,'enabled_tools_count':allowed_count,'disabled_tools_count':blocked_count,
                       'evidence':f'{app}: declared MCP entry {index} in {reference}; {connection}; {state}; URL scheme: {scheme}; URL user-info present: {credentials}; auth-related setting present: {auth}; enabled_tools list count: {allowed_count}; disabled_tools list count: {blocked_count}. These are configuration facts, not effective permissions or proof of authentication. Raw identities and secret values are excluded.'})
    return result


def extract_codex(text):
    data=tomllib.loads(text)
    return extract_integrations({'mcpServers':data.get('mcp_servers',{})},'Codex')


def integrations():
    appdata=Path(os.environ.get('APPDATA',Path.home()/'AppData/Roaming'))
    targets=[('Claude Desktop',appdata/'Claude/claude_desktop_config.json'),
             ('Cursor',Path.home()/'.cursor/mcp.json'),
             ('VS Code',appdata/'Code/User/mcp.json'),
             ('Windsurf',Path.home()/'.codeium/windsurf/mcp_config.json'),
             ('Codex',Path(os.environ.get('CODEX_HOME',Path.home()/'.codex'))/'config.toml')]
    obs=[];read=missing=failed=0
    for app,path in targets:
        try:
            if path.stat().st_size>1024*1024:failed+=1;continue
            text=path.read_text(encoding='utf-8-sig')
            found=extract_codex(text) if app=='Codex' else extract_integrations(json.loads(text),app)
            obs.append({'kind':'configuration','service':app,'evidence':f'{app}: supported configuration file read; {len(found)} explicitly declared MCP connection(s). Other integrations, profiles and runtime permissions were not assessed.'})
            obs.extend(found);read+=1
        except FileNotFoundError:missing+=1
        except (OSError,ValueError,RecursionError):failed+=1
    status='partial' if failed and read else 'unavailable' if failed else 'complete'
    return obs,{'id':'integrations','status':status,'detail':f'{read} supported JSON/TOML files read, {missing} absent, {failed} unavailable or unsupported; {sum(o["kind"]=="integration" for o in obs)} declared MCP connections extracted. A read file may contain zero supported connections. JSON-with-comments, plugin-managed integrations, alternate profiles and runtime permissions are outside coverage.'}


def known_locations():
    local=Path(os.environ.get('LOCALAPPDATA',Path.home()/'AppData/Local'))
    targets=[('Ollama',Path.home()/'.ollama'),('LM Studio',Path.home()/'.lmstudio'),
             ('Codex',Path(os.environ.get('CODEX_HOME',Path.home()/'.codex'))),
             ('Claude',Path.home()/'.claude'),('Ollama',local/'Programs/Ollama'),
             ('LM Studio',local/'Programs/LM Studio'),('Claude',local/'AnthropicClaude')]
    obs=[];failed=0
    for label,path in targets:
        try:
            import stat
            if stat.S_ISDIR(path.stat().st_mode):
                obs.append({'kind':'artifact','service':label,'evidence':f'{label}: a supported named directory exists. Contents were not inspected. It may be a remnant and does not prove an active installation.'})
        except FileNotFoundError:continue
        except OSError:failed+=1
    obs=list({o['service']:o for o in obs}.values())
    return obs,{'id':'locations','status':'partial' if failed else 'complete','detail':f'Checked {len(targets)} fixed directory locations without recursion or reading contents; {len(obs)} supported matches, {failed} unavailable. Other locations are outside coverage.'}


def collect(options):
    observations=[];coverage=[]
    for id, function in [('installed',installed_apps),('packages',packages),('running',running),('listeners',listeners),('integrations',integrations),('locations',known_locations)]:
        selected=options.get('installed') if id=='packages' else options.get(id)
        if not selected:
            coverage.append({'id':id,'status':'skipped','detail':'Not selected. No conclusion can be drawn about this source.'});continue
        if sys.platform != 'win32':
            coverage.append({'id':id,'status':'unavailable','detail':'This preview supports Windows only.'});continue
        try:
            obs,status=function();observations.extend(obs);coverage.append(status)
        except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
            coverage.append({'id':id,'status':'unavailable','detail':'Could not complete this check. It may be unavailable, restricted or unsupported. No absence or safety conclusion is implied.'})
    return observations,coverage
