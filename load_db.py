"""Module for fetching and loading KEV data"""

import requests

import kev_schema as kev


def fetch_data():
    """Fetch data from CISA.gov KEV"""
    with requests.get(kev.URL_JSON_DB, timeout=15) as r:
        data = r.json()
        return data


def search_cpe(vulnerabilities, cve):
    """Search for CVE [cve] in KEV dataset [vulnerabilities]"""
    for vuln in vulnerabilities:
        if cve == vuln[kev.VULN_CVE]:
            yield vuln


# pylint: disable=W0105
"""
if __name__ == "__main__":
    data = fetch_data()
    print(data[DOC_TITLE])
    print(data[DOC_VER])
    print(data[DOC_TIMESTAMP])
    for object in data[DOC_VULNERABILITIES]:
        print(object[VULN_CVE])

    for x in search_cpe(data[DOC_VULNERABILITIES], "CVE-2024-1709"):
        print(x)
    print(len(data[DOC_VULNERABILITIES]))

"""
