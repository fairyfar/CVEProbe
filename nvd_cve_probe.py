#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import json
import codecs
import time
import datetime
import sys
import copy
import re

CVE_DETAIL = "https://nvd.nist.gov/vuln/detail/"
CPE_MATCH_RE = r"^cpe:2.3:.:%s:%s:"

DIR_DATA = "./data"
DIR_CVE = "%s/cve" % (DIR_DATA)
DIR_CPEMATCH = "%s/cpematch" % (DIR_DATA)
CONFIG_FILE = "./config/config.json"
REPORT_DIR = "./report"
# Brief/Summary report
REPORT_CVE = "%s/cve.csv" % (REPORT_DIR)
# Detail report
REPORT_CVE_DETAIL = "%s/cve_detail.csv" % (REPORT_DIR)

def process_args():
    """
    Process options
    """
    global CONFIG_FILE
    global DIR_DATA
    global DIR_CVE
    global DIR_CPEMATCH
    global REPORT_DIR
    global REPORT_CVE
    global REPORT_CVE_DETAIL

    parser = argparse.ArgumentParser(description="The \"probe\" part of the CVEProbe project.")
    parser.add_argument("-c", "--config", type = str, default = "", \
        help = "configuration file (default is %s)" % (CONFIG_FILE))
    parser.add_argument("-d", "--data", type = str, default = "", \
        help = "data directory (default is %s)" % (DIR_DATA))
    parser.add_argument("-r", "--report", type = str, default = "", \
        help = "report directory (default is %s)" % (REPORT_DIR))

    args = parser.parse_args()
    if args.config != "":
        CONFIG_FILE = args.config
    if args.data != "":
        DIR_DATA = args.data
        DIR_CVE = "%s/cve" % (DIR_DATA)
        DIR_CPEMATCH = "%s/cpematch" % (DIR_DATA)
    if args.report != "":
        REPORT_DIR = args.report
        REPORT_CVE = "%s/cve.csv" % (REPORT_DIR)
        REPORT_CVE_DETAIL = "%s/cve_detail.csv" % (REPORT_DIR)

    return args

def log_print(ptype, pmsg):
    """
    Print log
    """
    log_str = "[%s] %-7s %s" % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "[" + ptype + "]", pmsg)
    print(log_str)
    sys.stdout.flush()

def ver_split(v):
    """
    Split version
    """
    parts = []
    for part in v.split('.'):
        # Handling the parts that consist of both numbers and letters (such as 1b)
        num_part = ''
        for ch in part:
            if ch.isdigit():
                num_part += ch
            else:
                break
        parts.append(int(num_part) if num_part else 0)
        # Handle the suffixes of letters (such as beta/alpha, etc.)
        suffix = part[len(num_part):]
        if suffix:
            parts.append(suffix.lower())
    return parts

def ver_compare(v1, v2):
    """
    Compare the sizes of the two version numbers
    :param v1: Version number strings, such as "1.2.3"
    :param v2: Version number strings, such as "1.10.0"
    :return: 1(v1>v2), -1(v1<v2), 0(v1==v2)
    """
    parts1, parts2 = ver_split(v1), ver_split(v2)

    for p1, p2 in zip(parts1, parts2):
        if isinstance(p1, int) and isinstance(p2, int):
            if p1 > p2: return 1
            if p1 < p2: return -1
        else:
            # Comparison of letter suffixes (in alphabetical order)
            if str(p1) > str(p2): return 1
            if str(p1) < str(p2): return -1

    # Deal with the situation where the lengths are not consistent.
    if len(parts1) > len(parts2): return 1
    if len(parts1) < len(parts2): return -1
    return 0

def get_ver_from_criteria(criteria):
    """
    Get version from CPE criteria
    """
    crit_ary = criteria.split(':')
    return crit_ary[5]

def ver_matched(versions, cpematch):
    """
    Matche versions in the CPE.
    :param versions: List of versions
    :param cpematch: matchString of CPE
    :return: List of matched versions
    """
    ver_ls = []
    # Specific version
    if "matches" in cpematch:
        for match in cpematch["matches"]:
            name_ary = match["cpeName"].split(':')
            if len(name_ary) <= 5:
                continue
            for ver in versions:
                if (ver == name_ary[5] or ver == "") and ver not in ver_ls:
                    ver_ls.append(ver)
        return ver_ls

    # Range version
    ver_ls = copy.deepcopy(versions)
    ver_key = 0
    if "versionStartIncluding" in cpematch:
        ver_key = ver_key | 1
        for i in range(len(ver_ls)-1, -1, -1):
            cmp = ver_compare(ver_ls[i], cpematch["versionStartIncluding"])
            if cmp == -1 and ver_ls[i] != "":
                ver_ls.pop(i)
    if "versionStartExcluding" in cpematch:
        ver_key = ver_key | 2
        for i in range(len(ver_ls)-1, -1, -1):
            cmp = ver_compare(ver_ls[i], cpematch["versionStartExcluding"])
            if cmp <= 0 and ver_ls[i] != "":
                ver_ls.pop(i)
    if "versionEndIncluding" in cpematch:
        ver_key = ver_key | 4
        for i in range(len(ver_ls)-1, -1, -1):
            cmp = ver_compare(ver_ls[i], cpematch["versionEndIncluding"])
            if cmp == 1 and ver_ls[i] != "":
                ver_ls.pop(i)
    if "versionEndExcluding" in cpematch:
        ver_key = ver_key | 8
        for i in range(len(ver_ls)-1, -1, -1):
            cmp = ver_compare(ver_ls[i], cpematch["versionEndExcluding"])
            if cmp >= 0 and ver_ls[i] != "":
                ver_ls.pop(i)

    # No any range
    if ver_key == 0:
        crit_ver = get_ver_from_criteria(cpematch["criteria"])
        for i in range(len(ver_ls)-1, -1, -1):
            if ver_ls[i] != crit_ver and ver_ls[i] != "":
                ver_ls.pop(i)

    return ver_ls

def load_config_file():
    """
    Load config list
    """
    config_fn = CONFIG_FILE
    log_print("INFO", "Load " + config_fn)
    try:
        with codecs.open(config_fn, "r", encoding = "utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_print("ERROR", "Load %s failed." % (CONFIG_FILE))
        exit(1)

def load_cve_cve(vendor, product):
    """
    Load CVE & CPEMatch
    """
    fn = "%s%s" % ("" if vendor == "" else vendor + "_", product)
    log_print("INFO", "Probe " + fn)
    cve_fn = "%s/%s.json" % (DIR_CVE, fn)
    cpematch_fn = "%s/%s.json" % (DIR_CPEMATCH, fn)

    cves_json = None
    cpematchs_json = None
    try:
        with codecs.open(cve_fn, "r", encoding = "utf-8") as f:
            cves_json = json.load(f)
    except Exception as e:
        log_print("ERROR", "CVE file failed")
    try:
        with codecs.open(cpematch_fn, "r", encoding = "utf-8") as f:
            cpematchs_json = json.load(f)
    except Exception as e:
        log_print("ERROR", "CPEMatch file failed")

    return cves_json, cpematchs_json

def find_cpe_cid(cpe_matches, criteria_id):
    """
    Find matchString via matchCriteriaId
    """
    for match_str in cpe_matches["matchStrings"]:
        if match_str["matchString"]["matchCriteriaId"] == criteria_id:
            return match_str["matchString"]
    return None

def verify_cves(vers, cve, valid_cves):
    """
    Verify CVEs
    """
    for i in range(len(vers)-1, -1, -1):
        ver_cve = {"ver": vers[i], "cve": cve["id"]}
        if ver_cve in valid_cves:
            vers.pop(i)
        else:
            valid_cves.append(ver_cve)

def get_cve_description(cve):
    """
    Get description from CVE and normalize it
    """
    for desc in cve["descriptions"]:
        if desc["lang"] == "en":
            return desc["value"].replace("\"", "\"\"")
    return ""

def get_cvss_rank(ver, cve):
    """
    Get CVSS rank
    """
    cvem = cve["metrics"]
    if ver == "V2" and "cvssMetricV2" in cvem:
        cvss = cvem["cvssMetricV2"][0]
        return "%s" % str(cvss["cvssData"]["baseScore"]), cvss["baseSeverity"], cvss["cvssData"]["vectorString"]
    elif ver == "V30" and "cvssMetricV30" in cvem:
        cvss = cvem["cvssMetricV30"][0]
        return "%s" % str(cvss["cvssData"]["baseScore"]), cvss["cvssData"]["baseSeverity"], cvss["cvssData"]["vectorString"]
    elif ver == "V31" and "cvssMetricV31" in cvem:
        cvss = cvem["cvssMetricV31"][0]
        return "%s" % str(cvss["cvssData"]["baseScore"]), cvss["cvssData"]["baseSeverity"], cvss["cvssData"]["vectorString"]
    elif ver == "V40" and "cvssMetricV40" in cvem:
        cvss = cvem["cvssMetricV40"][0]
        return "%s" % str(cvss["cvssData"]["baseScore"]), cvss["cvssData"]["baseSeverity"], cvss["cvssData"]["vectorString"]
    else:
        return "N/A", "N/A", "N/A"

def str2date(date_str):
    """
    YYYY-MM-DDTHH:MM:SS.MMM --> YYYY-MM-DD
    """
    try:
        date_obj = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
        return date_obj.strftime("%Y-%m-%d")
    except:
        log_print("ERROR", "%s format failed" % date_str)
        return ""

def output_probe(fsum, fdet, vendor, product, versions, cve):
    """
    Output probe result
    """
    for ver in versions:
        sum_csv = "%s,%s,%s,%s,%s,%s%s" % ( \
            vendor, product, ver[0], cve["id"], cve["vulnStatus"], CVE_DETAIL, cve["id"])

        v2_score, v2_sev, v2_vect = get_cvss_rank("V2", cve)
        v30_score, v30_sev, v30_vect = get_cvss_rank("V30", cve)
        v31_score, v31_sev, v31_vect = get_cvss_rank("V31", cve)
        v40_score, v40_sev, v40_vect = get_cvss_rank("V40", cve)
        # There are 5 reserved fields
        det_csv = "%s,\"%s\",%s,%s,%s,%s,\"%s\",%s,%s,\"%s\",%s,%s,\"%s\",%s,%s,\"%s\",,,,,,\"%s\"\n" % ( \
            sum_csv, \
            ver[1], \
            str2date(cve["published"]), str2date(cve["lastModified"]), \
            v2_score, v2_sev, v2_vect, v30_score, v30_sev, v30_vect, v31_score, v31_sev, v31_vect, v40_score, v40_sev, v40_vect, \
            get_cve_description(cve))

        fsum.write(sum_csv)
        fsum.write("\n")
        fdet.write(det_csv)
    return len(versions)

def cve_probe(configs, fsum, fdet):
    """
    Probe CVE
    """
    cve_cnt = 0
    # Traversal modules
    for modu in configs["modules"]:
        vendor = modu["vendor"].lower()
        product = modu["product"].lower()
        cves, cpematches = load_cve_cve(vendor, product)
        modu_cve_cnt = 0

        if cves == None or cpematches == None:
            continue
        if len(cves["vulnerabilities"]) < 1:
            log_print("INFO", "No CVE")
            continue
        if len(cpematches["matchStrings"]) < 1:
            log_print("INFO", "No CPEMatch")
            continue

        versions = modu["version"]
        # re string
        re_str = CPE_MATCH_RE % (r".*" if vendor == "" else vendor, product)

        # Traversal CVEs
        for cve in cves["vulnerabilities"]:
            if "cve" not in cve:
                continue
            cvecve = cve["cve"]
            if "configurations" not in cvecve:
                continue
            # Excluded CVE
            if cvecve["id"] in configs["excluded_cve"]:
                log_print("INFO", "%s is excluded" % (cvecve["id"]))
                continue

            valid_cves = []
            confs = cvecve["configurations"]
            for conf in confs:
                for node in conf["nodes"]:
                    for cpeMatch in node["cpeMatch"]:
                        criteria = cpeMatch["criteria"]
                        if re.match(re_str, criteria) == None:
                            continue

                        matchString = find_cpe_cid(cpematches, cpeMatch["matchCriteriaId"])
                        if matchString == None:
                            continue
                        vers = ver_matched(versions, matchString)
                        if len(vers) == 0:
                            continue
                        verify_cves(vers, cvecve, valid_cves)
                        ret_cnt = output_probe(fsum, fdet, vendor, product, vers, cvecve)

                        modu_cve_cnt += ret_cnt
                        cve_cnt += ret_cnt
        log_print("INFO", "%d CVE vulnerabilities" % modu_cve_cnt if modu_cve_cnt > 0 else "No CVE")

    log_print("INFO", "There are %d CVE vulnerabilities" % cve_cnt)

def probe_main():
    """
    Main for probe
    """
    args = process_args()
    configs = load_config_file()
    log_print("INFO", configs["title"])

    with codecs.open(REPORT_CVE, "w", encoding = "utf-8-sig") as fsum, codecs.open(REPORT_CVE_DETAIL, "w", encoding = "utf-8-sig") as fdet:
        cve_probe(configs, fsum, fdet)

if __name__ == "__main__":
    probe_main()
