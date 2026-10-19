import unittest
from core import analyze, compare, html_report

def snapshot(observations=None, coverage=None, context=None):
    return analyze(observations or [], coverage or [], context or {})

class RulesTests(unittest.TestCase):
    def test_generic_port_is_not_identified_as_ai(self):
        r=snapshot([{'kind':'listener','service':'Unknown service','confirmed':False,'port':8000,'address':'0.0.0.0','evidence':'TCP listener'}])
        self.assertEqual(r['findings'],[])

    def test_confirmed_nonloopback_listener_is_not_called_internet_exposed(self):
        r=snapshot([{'kind':'listener','service':'Ollama','confirmed':True,'port':11434,'address':'0.0.0.0','evidence':'Recognized process and listener'}])
        self.assertEqual(len(r['findings']),1)
        self.assertIn('beyond loopback',r['findings'][0]['title'])
        self.assertIn('firewall',r['findings'][0]['limitation'])

    def test_failure_remains_unknown(self):
        r=snapshot(coverage=[{'id':'listeners','status':'unavailable','detail':'Permission unavailable'}])
        self.assertEqual(r['coverage'][0]['status'],'unavailable')
        self.assertEqual(r['findings'],[])
        self.assertNotIn('risk_score',r)

    def test_installed_tool_does_not_establish_business_use(self):
        r=snapshot([{'kind':'installed','service':'Claude','evidence':'Installed application record'}])
        self.assertEqual(r['findings'],[])

    def test_report_escapes_untrusted_text(self):
        r=snapshot([{'kind':'installed','service':'<script>alert(1)</script>','evidence':'test'}])
        text=html_report(r)
        self.assertNotIn('<script>alert(1)</script>',text)
        self.assertIn('&lt;script&gt;',text)

    def test_comparison_does_not_claim_resolution(self):
        old={'findings':[{'id':'old'}]};new={'findings':[{'id':'new'}]}
        result=compare(old,new)
        self.assertEqual(result,{'new':['new'],'unchanged':[],'no_longer_observed':['old']})

    def test_context_is_reported_not_verified(self):
        r=snapshot(context={'work_use':'yes','policy':'no','sensitive_data':'unsure'})
        f=next(f for f in r['findings'] if f['id']=='policy-review')
        self.assertEqual(f['basis'],'Reported')

    def test_inventory_reconciles_multiple_sources(self):
        r=snapshot([{'kind':'package','service':'Claude','evidence':'Package record'},
                    {'kind':'running','service':'Claude','evidence':'Process record'},
                    {'kind':'configuration','service':'Claude Desktop','evidence':'Settings file'}])
        self.assertEqual(len(r['inventory']),1)
        self.assertEqual(r['inventory'][0]['service'],'Claude')
        self.assertEqual(len(r['inventory'][0]['evidence']),3)
        self.assertEqual(r['findings'],[])

if __name__=='__main__':unittest.main()
