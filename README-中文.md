[中文](README-中文.md) | [ENGLISH](README.md)

CVEProbe项目——探测和检测软件CVE漏洞。

# 一、问题

使用第三方软件时，需要知晓其存在哪些已知漏洞。本项目解答以下问题：

“指定版本的软件存在哪些`CVE`漏洞？”。

# 二、功能

- 给定软件的制造商和产品名称，以及版本号，通过`NVD`获取存在哪些`CVE`漏洞。

- 支持一次搜索多个产品

- 支持每个产品搜索多个版本

- 以`CSV`格式输出扫描结果

# 三、运行环境

- OS：Windows/Linux

- Python 2或3

# 四、文件作用

- `nvd_cve_extract.py`：使用`NVD API`在线提取`CVE`和`CPE`信息

- `nvd_cve_probe.py`：离线探测`CVE`和`CPE`信息，输出`CVE`漏洞报告

- `extract.log`：`nvd_cve_extract.py`执行过程记录

- `config/config.json`：配置文件。配置需要扫描的软件名称和版本号。

- `data/cve`：提取到的`CVE`信息

- `data/cpematch`：提取到的`CPE Match`信息

- `report/cve.csv`：输出的简要报告

- `report/cve_detail.csv`：输出的详细报告

# 五、使用示例

1. 编辑配置文件`config/config.json`

2. 使用`nvd_cve_extract.py`提取`CVE`和`CPE`信息

```
$ python ./nvd_cve_extract.py
```

3. 使用`nvd_cve_probe.py`探测`CVE`和`CPE`信息

```
$ python ./nvd_cve_probe.py
```

# 六、注意事项

制造商名称和产品名称需要符合`NVD`规范，例如，`gtest`在`NVD`中注册的产品名称为`googletest`。

可以通过页面搜索核实：

https://nvd.nist.gov/products/cpe/search

# 七、开源协议

本项目遵循MIT开源协议。

Scripted by FairyFar. [www.200yi.com](http://www.200yi.com)
