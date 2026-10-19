import json
import unittest
from collectors import extract_integrations, match_app, parse_listeners, parse_packages, parse_processes, extract_codex

class CollectorTests(unittest.TestCase):
    def test_narrow_application_matching(self):
        self.assertEqual(match_app('Ollama 0.5.1'),'Ollama')
        self.assertIsNone(match_app('January Budget'))
        self.assertIsNone(match_app('AI Helper Antivirus'))

    def test_unknown_process_on_ai_port_is_ignored(self):
        text='TCP  0.0.0.0:8000  0.0.0.0:0  LISTENING  42'
        self.assertEqual(parse_listeners(text,{42:'python'}),[])

    def test_ipv6_listener(self):
        obs=parse_listeners('TCP [::1]:11434 [::]:0 LISTENING 42',{42:'ollama'})
        self.assertEqual(obs[0]['address'],'::1')

    def test_config_does_not_export_secrets(self):
        raw={'mcpServers':{'private-customer-name':{'command':'tool','args':['secret-argument'],
             'env':{'TOKEN':'super-secret'},'url':'https://example.test/path?token=secret-query'}}}
        output=json.dumps(extract_integrations(raw,'Example'))
        for forbidden in ['private-customer-name','secret-argument','super-secret','secret-query','example.test']:
            self.assertNotIn(forbidden,output)

    def test_package_discovery_matches_known_names_only(self):
        result=parse_packages([{'Name':'Claude','Version':'2.0'}, {'Name':'OpenAI.Codex','Version':'1.0'},
                               {'Name':'Contoso.NotReallyCodex','Version':'1.0'}])
        self.assertEqual({o['service'] for o in result},{'Claude','Codex'})

    def test_running_tools_do_not_need_listeners(self):
        result=parse_processes([{'Id':10,'ProcessName':'ChatGPT'},{'Id':11,'ProcessName':'codex'},
                                {'Id':12,'ProcessName':'codex'},{'Id':13,'ProcessName':'codex-helper'}])
        self.assertEqual({o['service'] for o in result},{'ChatGPT','Codex'})
        self.assertEqual(next(o for o in result if o['service']=='Codex')['count'],2)

    def test_codex_toml_does_not_export_values(self):
        raw='''model = "example-model"
[mcp_servers.private_label]
command = "example"
args = ["secret-argument"]
[mcp_servers.private_label.env]
TOKEN = "secret-token"
'''
        result=extract_codex(raw)
        self.assertEqual(len(result),1)
        text=json.dumps(result)
        for value in ['private_label','secret-argument','secret-token','example-model']:
            self.assertNotIn(value,text)

    def test_disabled_codex_connection_is_explicit(self):
        result=extract_codex('[mcp_servers.sample]\nurl="https://example.test"\nenabled=false')
        self.assertIn('disabled',result[0]['evidence'])

    def test_process_input_is_validated(self):
        with self.assertRaises(ValueError):parse_processes({'unexpected':'value'})

if __name__=='__main__':unittest.main()
