#! /usr/bin/python3

import urllib.request
import json

from kev_schema import *


def get_data():
    with urllib.request.urlopen(URL_JSON_DB) as url:
        data = json.load(url)
        return data


def search_cpe(vulnerabilities, cve):
    for vuln in vulnerabilities:
        if cve == vuln[VULN_CVE]:
            yield vuln


if __name__ == "__main__":
    data = get_data()
    # 	print(data.values())
    print(data[DOC_TITLE])
    print(data[DOC_VER])
    print(data[DOC_TIMESTAMP])
    for object in data[DOC_VULNERABILITIES]:
        print(object[VULN_CVE])

    for x in search_cpe(data[DOC_VULNERABILITIES], "CVE-2024-1709"):
        print(x)
    print(len(data[DOC_VULNERABILITIES]))
    # print(object.values())
