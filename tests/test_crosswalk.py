import json
import unittest
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import date

from core import analyze, html_report
from app import validate_request
from collectors import extract_integrations, parse_packages
from crosswalk import build_crosswalk, QUESTIONS, SOURCES


class CrosswalkTests(unittest.TestCase):
    def test_no_evidence_is_unknown_not_compliant_or_not_applicable(self):
        result = build_crosswalk([], [], {}, today=date(2026, 10, 19))
        self.assertTrue(all(c['status'] == 'Evidence needed' for c in result['controls']))
        self.assertEqual(next(s for s in result['sources'] if s['id'] == 'nyc-aedt')['applicability'], 'Needs context')
        self.assertFalse(result['catalog']['exhaustive'])

    def test_observation_is_partial_inventory_evidence_only(self):
        obs = [{'id': 'obs-001', 'kind': 'running', 'service': 'Codex', 'evidence': 'Process name'}]
        result = build_crosswalk(obs, [], {}, today=date(2026, 10, 19))
        inventory = next(c for c in result['controls'] if c['id'] == 'inventory')
        self.assertEqual(inventory['status'], 'Partial local evidence')
        self.assertEqual(inventory['evidence_ids'], ['obs-001'])
        self.assertIn('owner', inventory['needed'].lower())
        self.assertEqual(next(c for c in result['controls'] if c['id'] == 'testing')['status'], 'Evidence needed')

    def test_reported_yes_never_becomes_verified(self):
        result = build_crosswalk([], [], {'policy': 'yes', 'testing': 'no'})
        self.assertEqual(next(c for c in result['controls'] if c['id'] == 'policy')['status'], 'Reported; verify evidence')
        self.assertEqual(next(c for c in result['controls'] if c['id'] == 'testing')['status'], 'Reported gap')

    def test_applicability_requires_both_nyc_and_employment(self):
        result = build_crosswalk([], [], {'nyc': 'yes', 'employment': 'yes', 'federal': 'no'})
        sources = {s['id']: s for s in result['sources']}
        self.assertEqual(sources['nyc-aedt']['applicability'], 'Potentially relevant')
        self.assertEqual(sources['omb-25-21']['applicability'], 'Outside declared trigger')
        self.assertIn('not a legal exemption', sources['omb-25-21']['reason'])

    def test_catalog_expiry_is_visible(self):
        result = build_crosswalk([], [], {}, today=date(2027, 1, 1))
        self.assertEqual(result['catalog']['freshness'], 'Review overdue')
        self.assertTrue(all(s['url'].startswith('https://') for s in SOURCES))
        self.assertTrue(all(c['mappings'] for c in result['controls']))

    def test_context_validation_and_html_traceability(self):
        context = {q['id']: 'unsure' for q in QUESTIONS}
        validate_request({'options': {'installed': True}, 'context': context})
        with self.assertRaises(ValueError):
            validate_request({'options': {'installed': True}, 'context': {'federal': 'maybe'}})
        report = analyze([{'kind': 'running', 'service': 'Codex', 'evidence': '<unsafe>'}], [], context)
        self.assertEqual(report['observations'][0]['id'], 'obs-001')
        page = html_report(report)
        for text in ['U.S. source coverage', 'Readiness crosswalk', 'GOVERN 1.6', 'obs-001', 'Evidence needed']:
            self.assertIn(text, page)
        self.assertNotIn('<unsafe>', page)

    def test_richer_connection_evidence_excludes_secret_values(self):
        raw = {'mcpServers': {'secret-name': {'url': 'http://user:password@example.test/private?token=secret',
                'headers': {'Authorization': 'secret-header'}, 'env': {'TOKEN': 'secret-env'}, 'enabled': False}}}
        obs = extract_integrations(raw, 'Codex')[0]
        self.assertEqual(obs['transport'], 'remote URL')
        self.assertEqual(obs['enabled_state'], 'explicitly disabled')
        self.assertEqual(obs['url_scheme'], 'http')
        self.assertTrue(obs['url_credentials_present'])
        self.assertTrue(obs['auth_material_configured'])
        for secret in ['secret-name', 'password', 'example.test', 'secret-header', 'secret-env', '/private']:
            self.assertNotIn(secret, json.dumps(obs))
        report = analyze([obs], [], {})
        self.assertEqual(report['findings'], [])  # disabled is inventory, not an active risk claim

    def test_package_version_is_retained_but_not_arbitrary_strings(self):
        obs = parse_packages([{'Name': 'OpenAI.Codex', 'Version': '26.1013.1.0'}])[0]
        self.assertEqual(obs['version'], '26.1013.1.0')
        obs = parse_packages([{'Name': 'OpenAI.Codex', 'Version': 'secret-token'}])[0]
        self.assertNotIn('secret-token', json.dumps(obs))

    def test_unsupported_disable_flags_cannot_suppress_connection_review(self):
        obs = extract_integrations({'servers': {'invalid': None, 'valid': {'url': 'http://localhost:1234', 'enabled': False, 'disabled': True}}}, 'VS Code')
        self.assertEqual(obs[0]['entry_index'], 2)
        self.assertEqual(obs[0]['enabled_state'], 'activation state not verified')
        self.assertEqual(len(analyze(obs, [], {})['findings']), 2)

    def test_cli_context_is_validated_before_collection_and_can_tailor_report(self):
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder) / 'context.json'
            output = Path(folder) / 'report.json'
            profile.write_text(json.dumps({'nyc': 'yes', 'employment': 'yes'}))
            result = subprocess.run([sys.executable, 'app.py', 'scan', '--demo', '--context', str(profile), '--json', str(output)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(next(s for s in report['crosswalk']['sources'] if s['id'] == 'nyc-aedt')['applicability'], 'Potentially relevant')
            profile.write_text('{"nyc":"maybe"}')
            output2 = Path(folder) / 'invalid.json'
            result = subprocess.run([sys.executable, 'app.py', 'scan', '--demo', '--context', str(profile), '--json', str(output2)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output2.exists())


if __name__ == '__main__':
    unittest.main()
