#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import json
import codecs
import time
import datetime
import sys
import copy
try:
    # Python 3
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except ImportError:
    # Python 2
    from urllib2 import urlopen, Request, URLError, HTTPError

CVD_API_URL = {
    "cve": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cpematch": "https://services.nvd.nist.gov/rest/json/cpematch/2.0",
}
# Request an API Key from https://nvd.nist.gov/developers/request-an-api-key
#API_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "apiKey": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
API_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
# The NVD API has rate limitations
API_SLEEP = 5
API_RETURN_OK = 200

CVE_CPE_MATCH = "startIndex=%d&virtualMatchString=cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*"
CPE_SEARCH = "startIndex=%d&matchStringSearch=cpe:2.3:*:%s:%s:*"

CONFIG_FILE = "config/config.json"
LOG_FILE = "extract.log"
DIR_DATA = "data"
DIR_CVE = "%s/cve" % (DIR_DATA)
DIR_CPEMATCH = "%s/cpematch" % (DIR_DATA)

def process_args():
    parser = argparse.ArgumentParser(description="The \"extract\" part of the CVEProbe project.")
    parser.add_argument("-t", "--type", type = str, default = "", choices=["cve", "cpematch"], \
        help = "the type of data to be extracted")
    parser.add_argument("-c", "--config", type = str, default = "", \
        help = "specified configuration file (default is %s)" % (CONFIG_FILE))
    return parser.parse_args()

def python_major_ver():
    """
    Get python major version
    """
    return sys.version_info.major

def log_print(ptype, pmsg):
    """
    Print log
    """
    log_str = "[%s] %-7s %s" % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[" + ptype + "]", pmsg)
    print(log_str)
    sys.stdout.flush()
    with codecs.open(LOG_FILE, "a", encoding = "utf-8") as f:
        f.write(log_str + "\n")

def clear_log():
    """
    Clear log
    """
    with codecs.open(LOG_FILE, "w", encoding = "utf-8") as f:
        f.write("")

def make_get_request(req_type, params):
    """
    API caller
    """
    try:
        response = None
        full_url = "%s?%s" % (CVD_API_URL[req_type], params)
        req = Request(full_url, headers = API_HEADERS)
        response = urlopen(req, timeout=10)
        status = response.code if python_major_ver() == 2 else response.status
        data = response.read().decode('utf-8')
    except HTTPError as e:
        status = e.code
        data = str(e)
    except URLError as e:
        status = 0
        data = "URL Error: %s" % (e.reason)
    except Exception as e:
        status = 0
        data = "Error: %s" % (str(e))
    finally:
        if response != None:
            response.close()
    return status, data

def load_config_file(config_fn):
    """
    Load config list
    """
    if config_fn == "":
        config_fn = CONFIG_FILE
    log_print("INFO", "Load " + config_fn)
    try:
        with codecs.open(config_fn, "r", encoding = "utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_print("ERROR", "Load %s failed." % (config_fn))
        exit(1)

def extract_cve(configs):
    """
    Extract CVE
    """
    log_print("INFO", "===== Extract CVE =====")
    for modu in configs["modules"]:
        # Always use lowercase
        vendor = modu["vendor"].lower()
        product = modu["product"].lower()
        log_print("INFO", product + " " + ",".join(modu["version"]))
        res_ary = None
        offset_idx = 0
        while True:
            time.sleep(API_SLEEP)
            # Extract CVE via vendor & product.
            req_status, res_str = make_get_request("cve", CVE_CPE_MATCH % (offset_idx, "*" if vendor == "" else vendor, product))
            if req_status != API_RETURN_OK:
                log_print("ERROR", res_str)
                break
            # To JSON
            res_json = json.loads(res_str)

            if len(res_json["vulnerabilities"]) < 1:
                log_print("WARN", "No CVE")

            offset_idx = res_json["startIndex"]
            if offset_idx == 0:
                # The first page
                res_ary = copy.deepcopy(res_json["vulnerabilities"])
            else:
                res_ary.extend(res_json["vulnerabilities"])
            offset_idx += res_json["resultsPerPage"]

            # More than one page
            if offset_idx < res_json["totalResults"]:
                log_print("WARN", "There is more page")
            else:
                # Write CVE file
                fn = "%s/%s%s.json" % (DIR_CVE, "" if vendor == "" else vendor + "_", product)
                with codecs.open(fn, "w", encoding = "utf-8") as f:
                    json.dump({"vulnerabilities":res_ary}, f, indent=2)
                break

def extract_cpematch(configs):
    """
    Extract CPEMatch
    """
    log_print("INFO", "===== Extract CPEMatch =====")
    for modu in configs["modules"]:
        # Always use lowercase
        vendor = modu["vendor"].lower()
        product = modu["product"].lower()
        log_print("INFO", product)
        res_ary = None
        offset_idx = 0
        while True:
            time.sleep(API_SLEEP)
            # Extract CPEMatch via vendor & product.
            req_status, res_str = make_get_request("cpematch", CPE_SEARCH % (offset_idx, "*" if vendor == "" else vendor, product))
            if req_status != API_RETURN_OK:
                log_print("ERROR", res_str)
                break
            # To JSON
            res_json = json.loads(res_str)

            if len(res_json["matchStrings"]) < 1:
                log_print("WARN", "No CPEMatch")

            offset_idx = res_json["startIndex"]
            if offset_idx == 0:
                # The first page
                res_ary = copy.deepcopy(res_json["matchStrings"])
            else:
                res_ary.extend(res_json["matchStrings"])
            offset_idx += res_json["resultsPerPage"]

            # More than one page
            if offset_idx < res_json["totalResults"]:
                log_print("WARN", "There is more page")
            else:
                # Write CPEMatch file
                fn = "%s/%s%s.json" % (DIR_CPEMATCH, "" if vendor == "" else vendor + "_", product)
                with codecs.open(fn, "w", encoding = "utf-8") as f:
                    json.dump({"matchStrings":res_ary}, f, indent=2)
                break

def extract_main():
    """
    Main for extract
    """
    args = process_args()
    clear_log()
    configs = load_config_file(args.config)
    log_print("INFO", configs["title"])

    if args.type == "" or args.type == "cve":
        extract_cve(configs)
    if args.type == "" or args.type == "cpematch":
        extract_cpematch(configs)

if __name__ == "__main__":
    extract_main()
