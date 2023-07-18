#!/usr/bin/python3
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import requests
import json
import logging
import argparse

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper


BASE_URL = "https://cve.penterep.com/api/v1/"

class ptvulnsearcher:
    def __init__(self, args):
        logging.disable(logging.CRITICAL)
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.use_json = args.json
        self.args = args

    def load_json_data(self,vulns):
        vulns = json.loads(vulns)
        ptprinthelper.ptprint(
            ptprinthelper.out_ifnot(f"Found {len(vulns)} CVE Records", "INFO", self.use_json))
        for vuln in vulns:
            cveid = vuln["cve_id"]
            cwe = vuln["cwe_id"]
            cvss_vector = vuln["cvss_vector"]
            cvss_score = vuln["cvss_score"]
            desc = vuln["description"]
            vendor = vuln["vendor"]
            product_type = vuln["product_type"]
            product_name = vuln["product_name"]
            version = vuln["version"]
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f" ", "", self.use_json))
            ptprinthelper.ptprint(ptprinthelper.out_title_ifnot(
                f"{cveid}", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Cwe ID: ", color="TITLE")} {cwe}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("CVSS Vector: ", color="TITLE")} {cvss_vector}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("CVSS Score: ", color="TITLE")} {cvss_score}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Description: ", color="TITLE")} {desc}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Vendor: ", color="TITLE")} {vendor}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Product name: ", color="TITLE")} {product_name}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Product type: ", color="TITLE")} {product_type}', "", self.use_json))
            ptprinthelper.ptprint(
                ptprinthelper.out_ifnot(f'{ptprinthelper.get_colored_text("Version: ", color="TITLE")} {version}', "", self.use_json))
        ptprinthelper.ptprint(ptprinthelper.out_if(self.ptjsonlib.get_result_json(), "", self.use_json))
        sys.exit(0)

    def run(self):
        if self.args.cve:
            url = BASE_URL+"cve/%s" % self.args.cve
            vulns = requests.get(url).text
        elif self.args.vendor_name and self.args.product_name and self.args.product_version:
            url = BASE_URL+"vendor/%s/product/%s/version/%s" % (self.args.vendor_name,self.args.product_name,self.args.product_version)
            vulns = requests.get(url).text
        elif self.args.vendor_name and self.args.product_name:
            url = BASE_URL+"vendor/%s/product/%s" % (self.args.vendor_name,self.args.product_name)
            vulns = requests.get(url).text
        elif self.args.product_name and self.args.product_version:
            url = BASE_URL+"product/%s/version/%s" % (self.args.product_name,self.args.product_version)
            vulns = requests.get(url).text
        elif self.args.product_name:
            url = BASE_URL+"product/%s" % self.args.product_name
            vulns = requests.get(url).text
        elif self.args.vendor_name:
            url = BASE_URL+"vendor/%s" % self.args.vendor_name
            vulns = requests.get(url).text
        else:
            print("Invalid input!")
            return
        if self.args.json:
            print(vulns)
        else:
            print(self.load_json_data(vulns))

def get_help():
    return [
        {"description": ["ptvulnsearcher"]},
        {"description": [
            "Tool for searching CVE (Common Vulnerabilities and Exposures)"]},
        {"usage": ["ptvulnsearcher <options>"]},
        {"usage_example": [
            "ptvulnsearcher -s Apache v2.2",
        ]},
        {"options": [
            ["-cve","--cve", "<cve>", "Search based on CVE ID"],
            ["-vn","--vendor_name", "<vendor_name>", "Search based on vendor name"],
            ["-pn","--product_name","<product_name>", "Search based on product name"],
            ["-pv","--product_version","<product_version>", "Search based on product version"],
            ["-j","--json","","Output in JSON format"],
            ["-v","--version","","Show script version and exit"],
            ["-h","--help","","Show this help message and exit"],
        ]
        }]

def search_cve(search_string, search_cve):
    parameters = {"search": search_string, "cve": search_cve}
    response = requests.get(BASE_URL, params=parameters)
    response_json = response.json()
    return json.dumps(response_json['data'], indent=2)

def parse_args():
    parser = argparse.ArgumentParser(
        add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-cve","--cve")
    parser.add_argument("-vn","--vendor_name", dest="vendor_name")
    parser.add_argument("-pn","--product_name",dest="product_name")
    parser.add_argument("-pv","--product_version", dest="product_version")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-h","--help", action="store", help=get_help())

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptvulnsearcher"
    args = parse_args()
    script = ptvulnsearcher(args)
    script.run()

if __name__ == "__main__":
    main()