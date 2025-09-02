[中文](README-中文.md) | [ENGLISH](README.md)

CVEProbe project - Probing or checking CVE vulnerabilities for softwares.

# 1. Problem

When using third-party software, it is necessary to know what known vulnerabilities it has. This project answers the following questions:

"What `CVE` vulnerabilities exist in specified versions softwares?".

# 2. Features

- Given the vendor and product name of the software, as well as the version number, obtain through `NVD` which `CVE` vulnerabilities exist.

- Supports searching for multiple products at once.

- Supports searching multiple versions for each product.

- Output the scan results in `CSV` format.

# 3. Environment

- OS: Windows/Linux

- Python 2 or 3

# 4. The function of files

- `nvd_cve_extract.py`: Use the `NVD API` to extract the information of `CVE` and `CPE` online.

- `nvd_cve_probe.py`: Probe the information of `CVE` and `CPE` offline and output a `CVE` vulnerability report.

- `extract.log`: Execution process record for `nvd_cve_extract.py`.

- `config/config.json`: Configuration file, which configures the name and version number of the software to be scanned.

- `data/cve`: The extracted `CVE` information.

- `data/cpematch`: The extracted `CPE Match` information.

- `report/cve.csv`: The brief report.

- `report/cve_detail.csv`: The detailed report.

# 5. Example

1. Edit the configuration file `config/config.json`.

2. Use `nvd_cve_extract.py` to extract `CVE` and `CPE` information:

```
$ python ./nvd_cve_extract.py
```

3. Use `nvd_cve_probe.py` to probe `CVE` and `CPE` information:

```
$ python ./nvd_cve_probe.py
```

# 6. Cautions

The vendor and product name need to comply with the `NVD` specification. For example, the product name registered by `gtest` in the `NVD` is `googletest`.

You can verify it through the page search:

https://nvd.nist.gov/products/cpe/search

# 7. Open Source License

This project is released under the MIT license.

Scripted by FairyFar. [www.200yi.com](http://www.200yi.com)
