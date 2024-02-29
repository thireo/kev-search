import unittest


import requests 
import json

from kev_schema import *

class TestSchema(unittest.TestCase):

    schema = None

    def test_schema_is_online(self):
        r = requests.get(URL_JSON_SCHEMA)
        assert r.status_code == 200
        self.assertIsNotNone(r.json())
        schema = r.json()

    def test_schema_against_downloaded(self):
        r = requests.get(URL_JSON_SCHEMA)
        assert r.status_code == 200
        self.assertIsNotNone(r.json())
        schema = r.json()
        
        assert "cveID" in VULN_CVE
        assert DOC_VER in schema["properties"]
        assert DOC_COUNT in schema["properties"]
        assert DOC_TIMESTAMP in schema["properties"]
        assert DOC_VULNERABILITIES in schema["properties"]
        
        schema_vuln = schema["$defs"]["vulnerability"]["properties"]
        
        assert VULN_CVE in schema_vuln
        assert VULN_ACTION in schema_vuln
        assert VULN_DATE_ADDED in schema_vuln
        assert VULN_DESCRIPTION in schema_vuln
        assert VULN_DUE_DATE in schema_vuln
        assert VULN_KNOWN in schema_vuln
        assert VULN_NAME in schema_vuln
        assert VULN_NOTES in schema_vuln
        assert VULN_PRODUCT in schema_vuln
        assert VULN_VENDOR in schema_vuln