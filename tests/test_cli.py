import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from app import main

class CliTests(unittest.TestCase):
    def test_scan_subcommand_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            html=Path(directory)/'report.html';data=Path(directory)/'report.json'
            with patch.object(sys,'argv',['app','scan','--demo','--html',str(html),'--json',str(data)]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(),0)
            self.assertTrue(json.loads(data.read_text())['demo'])
            self.assertIn('Tool inventory',html.read_text(encoding='utf-8'))

    def test_colliding_output_paths_rejected_before_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report'
            with patch.object(sys,'argv',['app','scan','--html',str(path),'--json',str(path)]),patch('app.collect') as collector,contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):main()
                collector.assert_not_called()
            self.assertFalse(path.exists())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json';path.write_text('original')
            with patch.object(sys,'argv',['app','scan','--json',str(path)]),patch('app.collect') as collector,contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):main()
                collector.assert_not_called()
            self.assertEqual(path.read_text(),'original')

if __name__=='__main__':unittest.main()
