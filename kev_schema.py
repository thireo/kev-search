#! /usr/bin/python3


URL_JSON_DB = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_JSON_SCHEMA = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"


DOC_TITLE = "title"
DOC_VER = "catalogVersion"
DOC_TIMESTAMP = "dateReleased"
DOC_COUNT = "count"
DOC_VULNERABILITIES = "vulnerabilities"

VULN_CVE = "cveID"
VULN_VENDOR = "vendorProject"
VULN_PRODUCT = "product"
VULN_NAME = "vulnerabilityName"
VULN_DATE_ADDED = "dateAdded"
VULN_DESCRIPTION = "shortDescription"
VULN_ACTION = "requiredAction"
VULN_DUE_DATE = "dueDate"
VULN_KNOWN = "knownRansomwareCampaignUse"
VULN_NOTES = "notes"
