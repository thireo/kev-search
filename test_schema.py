"""Test workflow for KEV schema against CISA KEV schema"""

import requests

import kev_schema as kev


def test_schema_is_online():
    """Test KEV schema is downloadable"""
    r = requests.get(kev.URL_JSON_SCHEMA, timeout=15)
    assert r.status_code == 200
    assert r.json() is not None


def test_schema_against_downloaded():
    """Test schema against download schema"""
    r = requests.get(kev.URL_JSON_SCHEMA, timeout=15)
    assert r.status_code == 200
    assert r.json() is not None
    schema = r.json()

    assert "cveID" in kev.VULN_CVE
    assert kev.DOC_VER in schema["properties"]
    assert kev.DOC_COUNT in schema["properties"]
    assert kev.DOC_TIMESTAMP in schema["properties"]
    assert kev.DOC_VULNERABILITIES in schema["properties"]

    schema_vuln = schema["$defs"]["vulnerability"]["properties"]

    assert kev.VULN_CVE in schema_vuln
    assert kev.VULN_ACTION in schema_vuln
    assert kev.VULN_DATE_ADDED in schema_vuln
    assert kev.VULN_DESCRIPTION in schema_vuln
    assert kev.VULN_DUE_DATE in schema_vuln
    assert kev.VULN_KNOWN in schema_vuln
    assert kev.VULN_NAME in schema_vuln
    assert kev.VULN_NOTES in schema_vuln
    assert kev.VULN_PRODUCT in schema_vuln
    assert kev.VULN_VENDOR in schema_vuln
