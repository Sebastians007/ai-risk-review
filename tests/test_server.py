import json
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from app import make_server

class ServerTests(unittest.TestCase):
    def setUp(self):
        self.server=make_server(port=0,demo=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
    def call(self,path,body=None,token=True,origin=None,host=None):
        headers={}
        if token:headers['X-Review-Token']=self.server.state.token
        if origin:headers['Origin']=origin
        if host:headers['Host']=host
        if body is not None:headers['Content-Type']='application/json'
        return urlopen(Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers=headers),timeout=3)
    def test_missing_token_is_rejected(self):
        with self.assertRaises(HTTPError) as cm:self.call('/api/state',token=False)
        self.assertEqual(cm.exception.code,403)
    def test_foreign_origin_is_rejected_even_with_token(self):
        with self.assertRaises(HTTPError) as cm:self.call('/api/state',origin='https://evil.example')
        self.assertEqual(cm.exception.code,403)
    def test_wrong_host_is_rejected(self):
        with self.assertRaises(HTTPError) as cm:self.call('/',host='evil.example')
        self.assertEqual(cm.exception.code,403)
    def test_options_require_real_booleans(self):
        with self.assertRaises(HTTPError) as cm:self.call('/api/scan',{'options':{'installed':'false'}})
        self.assertEqual(cm.exception.code,400)
    def test_path_traversal_not_served(self):
        with self.assertRaises(HTTPError) as cm:self.call('/../core.py')
        self.assertEqual(cm.exception.code,404)
    def test_idle_has_no_fake_report(self):
        state=json.load(self.call('/api/state'))
        self.assertIsNone(state['report'])
    def test_unknown_baseline_rejected(self):
        with self.assertRaises(HTTPError) as cm:self.call('/api/scan',{'options':{'installed':True},'baseline':{'findings':[]}})
        self.assertEqual(cm.exception.code,400)
    def test_live_baseline_cannot_be_mixed_with_demo(self):
        with self.assertRaises(HTTPError) as cm:self.call('/api/scan',{'options':{'installed':True},'baseline':{'format':'ai-risk-review','schema_version':1,'demo':False,'findings':[]}})
        self.assertEqual(cm.exception.code,400)
    def test_unicode_token_is_rejected_without_crashing(self):
        req=Request(self.url+'/api/state',headers={'X-Review-Token':'\u00e9'})
        with self.assertRaises(HTTPError) as cm:urlopen(req,timeout=3)
        self.assertEqual(cm.exception.code,403)

if __name__=='__main__':unittest.main()
