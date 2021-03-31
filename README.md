# Online search hashes-based on VirusTotal-OTX
The Python Scripts to use for downloading static, dynamic analysis and comments from VirusTotal and OTX Alienvault

## Usage
  #### Download VirusTotal - Static Analysis 
  ```bash
  python3 VirusTotal_static_analysis.py --file b553641092e1a15e70f1229cb9ada0a47132f054
   ```
   ```json
  {
   "totale_av":76,
   "name_apt":"sLoad",
   "other_name_apt":null,
   "nazione":"Cybercrime",
   "vt":{
      "data":{
         "attributes":{
            "type_description":"Office Open XML Document",
            "tlsh":"T1DD72BE15C714BC1CD9E08B79806503EDFA0E0153E29556AE3425EAECEB94EAB173DCCE",
            "vhash":"6d43f7e34f30cafecd8113b3e404db05",
            "trid":[
               {
                  "file_type":"Word Microsoft Office Open XML Format document (with Macro)",
                  "probability":53
               },
               {
                  "file_type":"Word Microsoft Office Open XML Format document",
                  "probability":23.9
               },
               {
                  "file_type":"Open Packaging Conventions container",
                  "probability":17.8
               },
               {
                  "file_type":"ZIP compressed archive",
                  "probability":4
               },
               {
                  "file_type":"PrintFox/Pagefox bitmap (640x800)",
                  "probability":1
               }
            ],
            "creation_date":1606752060,
            "names":[
               "iencli12.dotm"
            ],
            "last_modification_date":1613479881,
            "type_tag":"docx",
            "times_submitted":1,
            "total_votes":{
               "harmless":0,
               "malicious":0
            },
            "size":16636,
            "popular_threat_classification":{
               "suggested_threat_label":"trojan.msoffice/sload",
               "popular_threat_category":[
                  [
                     "trojan",
                     17
                  ],
                  [
                     "dropper",
                     4
                  ]
               ],
               "popular_threat_name":[
                  [
                     "msoffice",
                     3
                  ],
                  [
                     "sload",
                     3
                  ],
                  [
                     "w97m",
                     2
                  ]
               ]
            },
            "last_submission_date":1607467413,
            "meaningful_name":"iencli12.dotm",
            "crowdsourced_ids_stats":{
               "info":0,
               "high":0,
               "medium":2,
               "low":0
            },
            "sandbox_verdicts":{
               "C2AE":{
                  "category":"undetected",
                  "sandbox_name":"C2AE",
                  "malware_classification":[
                     "UNKNOWN_VERDICT"
                  ]
               },
               "Yomi Hunter":{
                  "category":"malicious",
                  "sandbox_name":"Yomi Hunter",
                  "malware_classification":[
                     "MALWARE"
                  ]
               }
            },
            "sha256":"e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c",
            "type_extension":"docx",
            "tags":[
               "open-file",
               "exe-pattern",
               "url-pattern",
               "docx",
               "macros",
               "hide-app",
               "create-ole"
            ],
            "crowdsourced_ids_results":[
               {
                  "rule_category":"Potentially Bad Traffic",
                  "alert_severity":"medium",
                  "alert_context":[
                     {
                        "src_ip":"10.10.0.121",
                        "protocol":"IP"
                     }
                  ],
                  "rule_msg":"DECODE_IP_OPTION_SET",
                  "rule_source":"snort",
                  "rule_id":"444"
               },
               {
                  "rule_category":"Attempted Information Leak",
                  "alert_severity":"medium",
                  "alert_context":[
                     {
                        "src_ip":"10.10.0.121",
                        "protocol":"UDP",
                        "src_port":51706
                     }
                  ],
                  "rule_msg":"PSNG_UDP_PORTSWEEP_FILTERED",
                  "rule_source":"snort",
                  "rule_id":"23"
               }
            ],
            "last_analysis_date":1607652080,
            "unique_sources":1,
            "first_submission_date":1607467413,
            "ssdeep":"192:HNmtT7KlBpGK6SICieyOA8MS48TuX63hOZ73Ea5l/aZTbYh7e++9dQEwPwS7mZNq:tmtvKBvnpDALoa5lahYY+ISJkm",
            "bundle_info":{
               "highest_datetime":"1980-01-01 00:00:00",
               "lowest_datetime":"1980-01-01 00:00:00",
               "num_children":14,
               "extensions":{
                  "xml":10,
                  "bin":1
               },
               "file_types":{
                  "XML":13,
                  "Microsoft Office":1
               },
               "type":"DOCX",
               "uncompressed_size":62573
            },
            "md5":"aa37daeedf69b6d26081c1d6ae5a19c3",
            "sha1":"b553641092e1a15e70f1229cb9ada0a47132f054",
            "magic":"Zip archive data, at least v2.0 to extract",
            "last_analysis_stats":{
               "harmless":0,
               "type-unsupported":10,
               "suspicious":0,
               "confirmed-timeout":0,
               "timeout":0,
               "failure":0,
               "malicious":31,
               "undetected":35
            },
            "last_analysis_results":{
               "Bkav":{
                  "category":"undetected",
                  "engine_name":"Bkav",
                  "engine_version":"1.3.0.9899",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Elastic":{
                  "category":"malicious",
                  "engine_name":"Elastic",
                  "engine_version":"4.0.13",
                  "result":"malicious (high confidence)",
                  "method":"blacklist",
                  "engine_update":"20201204"
               },
               "Cynet":{
                  "category":"malicious",
                  "engine_name":"Cynet",
                  "engine_version":"4.0.0.24",
                  "result":"Malicious (score: 85)",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "FireEye":{
                  "category":"malicious",
                  "engine_name":"FireEye",
                  "engine_version":"32.36.1.0",
                  "result":"Trojan.GenericKD.44924956",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "CAT-QuickHeal":{
                  "category":"undetected",
                  "engine_name":"CAT-QuickHeal",
                  "engine_version":"14.00",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "ALYac":{
                  "category":"undetected",
                  "engine_name":"ALYac",
                  "engine_version":"1.1.1.5",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Malwarebytes":{
                  "category":"undetected",
                  "engine_name":"Malwarebytes",
                  "engine_version":"3.6.4.335",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Zillya":{
                  "category":"undetected",
                  "engine_name":"Zillya",
                  "engine_version":"2.0.0.4242",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "AegisLab":{
                  "category":"malicious",
                  "engine_name":"AegisLab",
                  "engine_version":"4.2",
                  "result":"Trojan.MSOffice.SLoad.a!c",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Paloalto":{
                  "category":"type-unsupported",
                  "engine_name":"Paloalto",
                  "engine_version":"1.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Sangfor":{
                  "category":"undetected",
                  "engine_name":"Sangfor",
                  "engine_version":"1.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201207"
               },
               "Trustlook":{
                  "category":"undetected",
                  "engine_name":"Trustlook",
                  "engine_version":"1.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Alibaba":{
                  "category":"malicious",
                  "engine_name":"Alibaba",
                  "engine_version":"0.3.0.5",
                  "result":"TrojanDownloader:VBA/Obfuscation.A",
                  "method":"blacklist",
                  "engine_update":"20190527"
               },
               "K7GW":{
                  "category":"undetected",
                  "engine_name":"K7GW",
                  "engine_version":"11.155.35944",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "K7AntiVirus":{
                  "category":"undetected",
                  "engine_name":"K7AntiVirus",
                  "engine_version":"11.155.35943",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Arcabit":{
                  "category":"malicious",
                  "engine_name":"Arcabit",
                  "engine_version":"1.0.0.881",
                  "result":"Trojan.Generic.D2AD801C",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "BitDefenderTheta":{
                  "category":"undetected",
                  "engine_name":"BitDefenderTheta",
                  "engine_version":"7.2.37796.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201202"
               },
               "Cyren":{
                  "category":"malicious",
                  "engine_name":"Cyren",
                  "engine_version":"6.3.0.2",
                  "result":"Trojan.RZRC-5",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "SymantecMobileInsight":{
                  "category":"type-unsupported",
                  "engine_name":"SymantecMobileInsight",
                  "engine_version":"2.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20200813"
               },
               "Symantec":{
                  "category":"malicious",
                  "engine_name":"Symantec",
                  "engine_version":"1.13.0.0",
                  "result":"Trojan.Gen.NPE",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "TotalDefense":{
                  "category":"undetected",
                  "engine_name":"TotalDefense",
                  "engine_version":"37.1.62.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Baidu":{
                  "category":"undetected",
                  "engine_name":"Baidu",
                  "engine_version":"1.0.0.2",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20190318"
               },
               "TrendMicro-HouseCall":{
                  "category":"malicious",
                  "engine_name":"TrendMicro-HouseCall",
                  "engine_version":"10.0.0.1040",
                  "result":"Trojan.W97M.POWLOAD.THLOIBO",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Avast":{
                  "category":"malicious",
                  "engine_name":"Avast",
                  "engine_version":"21.1.5827.0",
                  "result":"Other:Malware-gen [Trj]",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "ClamAV":{
                  "category":"undetected",
                  "engine_name":"ClamAV",
                  "engine_version":"0.102.3.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Kaspersky":{
                  "category":"malicious",
                  "engine_name":"Kaspersky",
                  "engine_version":"15.0.1.13",
                  "result":"HEUR:Trojan-Downloader.MSOffice.SLoad.gen",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "BitDefender":{
                  "category":"malicious",
                  "engine_name":"BitDefender",
                  "engine_version":"7.2",
                  "result":"Trojan.GenericKD.44924956",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "NANO-Antivirus":{
                  "category":"undetected",
                  "engine_name":"NANO-Antivirus",
                  "engine_version":"1.0.146.25241",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "SUPERAntiSpyware":{
                  "category":"undetected",
                  "engine_name":"SUPERAntiSpyware",
                  "engine_version":"5.6.0.1032",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "MicroWorld-eScan":{
                  "category":"malicious",
                  "engine_name":"MicroWorld-eScan",
                  "engine_version":"14.0.409.0",
                  "result":"Trojan.GenericKD.44924956",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "APEX":{
                  "category":"type-unsupported",
                  "engine_name":"APEX",
                  "engine_version":"6.107",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Rising":{
                  "category":"malicious",
                  "engine_name":"Rising",
                  "engine_version":"25.0.0.26",
                  "result":"Dropper.Agent!8.2F (TOPIS:E0:SNE7OOM2KTI)",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Ad-Aware":{
                  "category":"malicious",
                  "engine_name":"Ad-Aware",
                  "engine_version":"3.0.16.117",
                  "result":"Trojan.GenericKD.44924956",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Sophos":{
                  "category":"undetected",
                  "engine_name":"Sophos",
                  "engine_version":"1.0.2.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Comodo":{
                  "category":"undetected",
                  "engine_name":"Comodo",
                  "engine_version":"33066",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "F-Secure":{
                  "category":"malicious",
                  "engine_name":"F-Secure",
                  "engine_version":"12.0.86.52",
                  "result":"Malware.VBS/Drop.Agent.lepeo",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "DrWeb":{
                  "category":"undetected",
                  "engine_name":"DrWeb",
                  "engine_version":"7.0.49.9080",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "VIPRE":{
                  "category":"undetected",
                  "engine_name":"VIPRE",
                  "engine_version":"88836",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "TrendMicro":{
                  "category":"malicious",
                  "engine_name":"TrendMicro",
                  "engine_version":"11.0.0.1006",
                  "result":"Trojan.W97M.POWLOAD.THLOIBO",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "McAfee-GW-Edition":{
                  "category":"malicious",
                  "engine_name":"McAfee-GW-Edition",
                  "engine_version":"v2019.1.2+3728",
                  "result":"BehavesLike.Downloader.lc",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Trapmine":{
                  "category":"type-unsupported",
                  "engine_name":"Trapmine",
                  "engine_version":"3.5.0.1023",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20200727"
               },
               "CMC":{
                  "category":"undetected",
                  "engine_name":"CMC",
                  "engine_version":"2.10.2019.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201204"
               },
               "Emsisoft":{
                  "category":"malicious",
                  "engine_name":"Emsisoft",
                  "engine_version":"2018.12.0.1641",
                  "result":"Trojan.GenericKD.44924956 (B)",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Ikarus":{
                  "category":"malicious",
                  "engine_name":"Ikarus",
                  "engine_version":"0.1.5.2",
                  "result":"Trojan-Dropper.VBA.Agent",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Avast-Mobile":{
                  "category":"undetected",
                  "engine_name":"Avast-Mobile",
                  "engine_version":"201210-00",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Jiangmin":{
                  "category":"undetected",
                  "engine_name":"Jiangmin",
                  "engine_version":"16.0.100",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Webroot":{
                  "category":"type-unsupported",
                  "engine_name":"Webroot",
                  "engine_version":"1.0.0.403",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Avira":{
                  "category":"malicious",
                  "engine_name":"Avira",
                  "engine_version":"8.3.3.10",
                  "result":"VBS/Drop.Agent.lepeo",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "eGambit":{
                  "category":"type-unsupported",
                  "engine_name":"eGambit",
                  "engine_version":null,
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Antiy-AVL":{
                  "category":"undetected",
                  "engine_name":"Antiy-AVL",
                  "engine_version":"3.0.0.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Kingsoft":{
                  "category":"undetected",
                  "engine_name":"Kingsoft",
                  "engine_version":"2017.9.26.565",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Gridinsoft":{
                  "category":"malicious",
                  "engine_name":"Gridinsoft",
                  "engine_version":"1.0.20.110",
                  "result":"Trojan.U.Downloader.oa",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Microsoft":{
                  "category":"undetected",
                  "engine_name":"Microsoft",
                  "engine_version":"1.1.17700.4",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "ViRobot":{
                  "category":"malicious",
                  "engine_name":"ViRobot",
                  "engine_version":"2014.3.20.0",
                  "result":"DOC.Z.Agent.16636",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "ZoneAlarm":{
                  "category":"malicious",
                  "engine_name":"ZoneAlarm",
                  "engine_version":"1.0",
                  "result":"HEUR:Trojan-Downloader.MSOffice.SLoad.gen",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "GData":{
                  "category":"malicious",
                  "engine_name":"GData",
                  "engine_version":"A:25.27963B:27.21181",
                  "result":"Trojan.GenericKD.44924956",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "TACHYON":{
                  "category":"undetected",
                  "engine_name":"TACHYON",
                  "engine_version":"2020-12-11.01",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "BitDefenderFalx":{
                  "category":"type-unsupported",
                  "engine_name":"BitDefenderFalx",
                  "engine_version":"2.0.936",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20200916"
               },
               "AhnLab-V3":{
                  "category":"undetected",
                  "engine_name":"AhnLab-V3",
                  "engine_version":"3.19.3.10105",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Acronis":{
                  "category":"undetected",
                  "engine_name":"Acronis",
                  "engine_version":"1.1.1.80",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201023"
               },
               "McAfee":{
                  "category":"malicious",
                  "engine_name":"McAfee",
                  "engine_version":"6.0.6.653",
                  "result":"RDN/Generic Downloader.x",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "MAX":{
                  "category":"malicious",
                  "engine_name":"MAX",
                  "engine_version":"2019.9.16.1",
                  "result":"malware (ai score=87)",
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "VBA32":{
                  "category":"undetected",
                  "engine_name":"VBA32",
                  "engine_version":"4.4.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Cylance":{
                  "category":"type-unsupported",
                  "engine_name":"Cylance",
                  "engine_version":"2.3.1.101",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Zoner":{
                  "category":"undetected",
                  "engine_name":"Zoner",
                  "engine_version":"0.0.0.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "ESET-NOD32":{
                  "category":"malicious",
                  "engine_name":"ESET-NOD32",
                  "engine_version":"22461",
                  "result":"a variant of VBA/TrojanDropper.Agent.BRD",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Tencent":{
                  "category":"undetected",
                  "engine_name":"Tencent",
                  "engine_version":"1.0.0.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201211"
               },
               "Yandex":{
                  "category":"undetected",
                  "engine_name":"Yandex",
                  "engine_version":"5.5.2.24",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "SentinelOne":{
                  "category":"undetected",
                  "engine_name":"SentinelOne",
                  "engine_version":"4.7.0.7",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "MaxSecure":{
                  "category":"undetected",
                  "engine_name":"MaxSecure",
                  "engine_version":"1.0.0.1",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Fortinet":{
                  "category":"malicious",
                  "engine_name":"Fortinet",
                  "engine_version":"6.2.142.0",
                  "result":"VBA/Agent.GBWDLEV!tr.dldr",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "AVG":{
                  "category":"malicious",
                  "engine_name":"AVG",
                  "engine_version":"21.1.5827.0",
                  "result":"Other:Malware-gen [Trj]",
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "Cybereason":{
                  "category":"type-unsupported",
                  "engine_name":"Cybereason",
                  "engine_version":"1.2.449",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20190616"
               },
               "Panda":{
                  "category":"undetected",
                  "engine_name":"Panda",
                  "engine_version":"4.6.4.2",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20201210"
               },
               "CrowdStrike":{
                  "category":"type-unsupported",
                  "engine_name":"CrowdStrike",
                  "engine_version":"1.0",
                  "result":null,
                  "method":"blacklist",
                  "engine_update":"20190702"
               },
               "Qihoo-360":{
                  "category":"malicious",
                  "engine_name":"Qihoo-360",
                  "engine_version":"1.0.0.1120",
                  "result":"Generic/Trojan.Downloader.3f4",
                  "method":"blacklist",
                  "engine_update":"20201211"
               }
            },
            "reputation":0
         },
         "type":"file",
         "id":"e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c",
         "links":{
            "self":"https://www.virustotal.com/api/v3/files/e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c"
         }
      }
   }
}
  ```
  
  
  
  #### Download VirusTotal - Dynamic Analysis
  ```bash
  python3 VirusTotal_dynamic_analysis.py --file b553641092e1a15e70f1229cb9ada0a47132f054
  ```
  ```json
  {
   "meta":{
      "count":2
   },
   "data":[
      {
         "attributes":{
            "verdicts":[
               "UNKNOWN_VERDICT"
            ],
            "command_executions":[
               "\"%ProgramFiles(x86)%\\Microsoft Office\\Office14\\WINWORD.EXE\" %SAMPLEPATH%"
            ],
            "registry_keys_set":[
               {
                  "value":"LowDateTime:-331231481,HighDateTime:30676316***Binary mof failed, see WMIPROV.LOG",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\ndis.sys[MofResourceName]"
               },
               {
                  "value":"LowDateTime:418629328,HighDateTime:30487037***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\System32\\Drivers\\portcls.SYS[PortclsMof]"
               },
               {
                  "value":"LowDateTime:1237199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\ACPI.sys.mui[ACPIMOFResource]"
               },
               {
                  "value":"LowDateTime:-227274444,HighDateTime:30116024***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\HDAudBus.sys[HDAudioMofName]"
               },
               {
                  "value":"LowDateTime:1137199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\System32\\Drivers\\en-US\\portcls.SYS.mui[PortclsMof]"
               },
               {
                  "value":"LowDateTime:302488720,HighDateTime:30778805***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\advapi32.dll[MofResourceName]"
               },
               {
                  "value":"LowDateTime:369951187,HighDateTime:30778805***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\en-US\\advapi32.dll.mui[MofResourceName]"
               },
               {
                  "value":"LowDateTime:1497199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\mssmbios.sys.mui[MofResource]"
               },
               {
                  "value":"LowDateTime:-377767680,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\en-US\\HDAudBus.sys.mui[HDAudioMofName]"
               },
               {
                  "value":"LowDateTime:382232320,HighDateTime:30016580***Binary mof failed, see WMIPROV.LOG",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\ndis.sys.mui[MofResourceName]"
               },
               {
                  "value":"LowDateTime:-577767680,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\en-US\\intelppm.sys.mui[PROCESSORWMI]"
               },
               {
                  "value":"LowDateTime:803713417,HighDateTime:0***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\IDE\\DiskAMDX_HARDDISK___________________________2.5+____\\5&2770a7af&0&0.0.0_0-{05901221-D566-11d1-B2F0-00A0C9062910}"
               },
               {
                  "value":"LowDateTime:-445445610,HighDateTime:30778799***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\intelppm.sys[PROCESSORWMI]"
               },
               {
                  "value":"LowDateTime:398767260,HighDateTime:30646967***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\ACPI.sys[ACPIMOFResource]"
               },
               {
                  "value":"LowDateTime:-1637837527,HighDateTime:30762899***Binary mof failed, see WMIPROV.LOG",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\monitor.sys[MonitorWMI]"
               },
               {
                  "value":"LowDateTime:-649833737,HighDateTime:30733938***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\mssmbios.sys[MofResource]"
               },
               {
                  "value":"26507113",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\Trusted Documents\\LastPurgeTime"
               },
               {
                  "value":"4C 00 00 00 A3 01 00 00 01 00 00 00 02 01 FF FF BD 00 00 00 00 00 00 00 00 00 10 00 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 01 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 1B 00 00 00 01 00 42 72",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Data\\Toolbars"
               },
               {
                  "value":"PCI\\VEN_8086&DEV_100E&SUBSYS_11001AF4&REV_03\\3&13C0B0C5&0&90",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\{B5DA8633-954C-4495-AE46-0BB5B5FB1CDC}\\Connection\\PnpInstanceID"
               },
               {
                  "value":"Global\\MMF_BITS_s",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\BITS\\Performance\\PerfMMFileName"
               },
               {
                  "value":"1",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{ad498944-762f-11d0-8dcb-00c04fc3358c}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\#{78032B7E-4968-42D3-9F37-287EA86C0AAA}\\Control\\Linked"
               },
               {
                  "value":"\\\\?\\SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\{78032B7E-4968-42D3-9F37-287EA86C0AAA}",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{ad498944-762f-11d0-8dcb-00c04fc3358c}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\#{78032B7E-4968-42D3-9F37-287EA86C0AAA}\\SymbolicLink"
               },
               {
                  "value":"1",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\ConfigValueEssNeedsLoading"
               },
               {
                  "value":"00 00 54 00 45 00 76 00 65 00 6E 00 74 00 4C 00 6F 00 67 00 45 00 76 00 65 00 6E 00 74 00 43 00 6F 00 6E 00 73 00 75 00 6D 00 65 00 72 00",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\CIMOM\\List of event-active namespaces"
               },
               {
                  "value":"%windir%\\System32\\Bits.log\n",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup\\BITS_LOG"
               },
               {
                  "value":"%windir%\\System32\\Bits.bak\n",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup\\BITS_BAK"
               },
               {
                  "value":"6F 3E 2B 00 54 0A 00 00 06 00 00 00 01 00 00 00 4A 00 00 00 02 00 00 00 3A 00 00 00 04 00 00 00 63 00 3A 00 5C 00 74 00 6D 00 70 00 5C 00 7A 00 37 00 67 00 72 00 73 00 37 00 6D 00 71 00 75 00 6F 00 6C 00 70 00 7A 00 62 00 31 00 6C 00 2E 00 64 00 6F 00 63 00 6D 00 00 00 00 00 00 00",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Resiliency\\StartupItems\\o>+"
               },
               {
                  "value":"6D 39 2B 00 54 0A 00 00 01 00 00 00 00 00 00 00 00 00 00 00",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Resiliency\\StartupItems\\m9+"
               },
               {
                  "value":"38 3A 2B 00 54 0A 00 00 04 00 00 00 00 00 00 00 8E 00 00 00 01 00 00 00 86 00 00 00 3F 00 43 00 3A 00 5C 00 55 00 73 00 65 00 72 00 73 00 5C 00 57 00 41 00 4C 00 4B 00 45 00 52 00 5C 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5C 00 52 00 6F 00 61 00 6D 00 69 00 6E 00 67 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 54 00 65 00 6D 00 70 00 6C 00 61 00 74 00 65 00 73 00 5C 00 4E 00 6F 00 72 00 6D 00 61 00 6C 00 2E 00 64 00 6F 00 74 00 6D 00 00 00 00 00 00 00",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Resiliency\\StartupItems\\8:+"
               },
               {
                  "value":"12642",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Last Counter"
               },
               {
                  "value":"12476 12482 12492 12502 12522 12566 12576 12614 12620 12636",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Object List"
               },
               {
                  "value":"12643",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Last Help"
               },
               {
                  "value":"12476",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\First Counter"
               },
               {
                  "value":"12477",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\First Help"
               },
               {
                  "value":"WmiApRpl.ini\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\PerfIniFile"
               },
               {
                  "value":"SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}\\asyncmac",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{cac88484-7515-4c03-82e6-71a87abac361}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{cac88484-7515-4c03-82e6-71a87abac361}\\DeviceInstance"
               },
               {
                  "value":"1",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{ad498944-762f-11d0-8dcb-00c04fc3358c}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\Control\\ReferenceCount"
               },
               {
                  "value":"A0 05 00 00 A0 0A A8 86 B7 32 D6 01 00 00 00 00 54 0A 00 00 60 7A A9 AF B7 32 D6 01 00 00 00 00",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\MTTT"
               },
               {
                  "value":"1",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\\\AutoDetect"
               },
               {
                  "value":"0",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\\\UNCAsIntranet"
               },
               {
                  "value":"On",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Common\\LanguageResources\\EnabledLanguages\\1033"
               },
               {
                  "value":"1",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{cac88484-7515-4c03-82e6-71a87abac361}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{cac88484-7515-4c03-82e6-71a87abac361}\\#\\Control\\Linked"
               },
               {
                  "value":"en-US\nen\n",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000_CLASSES\\Local Settings\\MuiCache\\17b\\52C64B7E\\LanguageList"
               },
               {
                  "value":"\\\\?\\SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{cac88484-7515-4c03-82e6-71a87abac361}",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{cac88484-7515-4c03-82e6-71a87abac361}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{cac88484-7515-4c03-82e6-71a87abac361}\\#\\SymbolicLink"
               },
               {
                  "value":"0",
                  "key":"HKLM\\SOFTWARE\\Microsoft\\WBEM\\PROVIDERS\\Performance\\Performance Refresh"
               },
               {
                  "value":"1",
                  "key":"HKLM\\SOFTWARE\\Microsoft\\WBEM\\PROVIDERS\\Performance\\Performance Refreshed"
               },
               {
                  "value":"28 1B 00 00 01 00 00 00 00 00 00 00 10 00 00 00 18 1B 00 00 09 00 00 00 9A 00 00 00 01 00 00 00 01 00 00 00 40 00 00 00 1A 00 00 00 5C 00 5C 00 2E 00 5C 00 72 00 6F 00 6F 00 74 00 5C 00 77 00 6D 00 69 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 01 00 00 04 00 00 00 08 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 64 00 00 00 68 00 00 00 3A 00 00 00 4D 00 53 00 69 00 53 00 43 00 53 00 49 00 5F 00 43 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 69 00 6F 00 6E 00 53 00 74 00 61 00 74 00 69 00 73 00 74 00 69 00 63 00 73 00 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 00 1A 00 00 00 49 00 6E 00 73 00 74 00 61 00 6E 00 63 00 65 00 4E 00 61 00 6D 00 65 00 00 00 2F 20 4D 6F 64 75 6C 65 20 4E 61 6D 65 3A 48 00 00 00 00 00 00 00 02 00 00 00 15 00 00 00 00 00 00 00 64 00 00 00 00 05 41 10 48 00 00 00 1C 00 00 00 42 00 79 00 74 00 65 00 73 00 52 00 65 00 63 00 65 00 69 00 76 00 65 00 64 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 04 00 00 00 15 00 00 00 00 00 00 00 64 00 00 00 00 05 41 10 40 00 00 00 14 00 00 00 42 0",
                  "key":"HKLM\\SOFTWARE\\Microsoft\\WBEM\\PROVIDERS\\Performance\\Performance Data"
               },
               {
                  "value":"LowDateTime:418629328,HighDateTime:30487037***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\System32\\Drivers\\portcls.SYS[PortclsMof]"
               },
               {
                  "value":"LowDateTime:-227274444,HighDateTime:30116024***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\HDAudBus.sys[HDAudioMofName]"
               },
               {
                  "value":"LowDateTime:1137199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\System32\\Drivers\\en-US\\portcls.SYS.mui[PortclsMof]"
               },
               {
                  "value":"LowDateTime:1497199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\en-US\\mssmbios.sys.mui[MofResource]"
               },
               {
                  "value":"LowDateTime:302488720,HighDateTime:30778805***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\advapi32.dll[MofResourceName]"
               },
               {
                  "value":"LowDateTime:369951187,HighDateTime:30778805***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\en-US\\advapi32.dll.mui[MofResourceName]"
               },
               {
                  "value":"LowDateTime:1237199616,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\en-US\\ACPI.sys.mui[ACPIMOFResource]"
               },
               {
                  "value":"LowDateTime:-377767680,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\en-US\\HDAudBus.sys.mui[HDAudioMofName]"
               },
               {
                  "value":"LowDateTime:382232320,HighDateTime:30016580***Binary mof failed, see WMIPROV.LOG",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\drivers\\en-US\\ndis.sys.mui[MofResourceName]"
               },
               {
                  "value":"LowDateTime:-577767680,HighDateTime:30016579***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\en-US\\intelppm.sys.mui[PROCESSORWMI]"
               },
               {
                  "value":"LowDateTime:803713417,HighDateTime:0***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\IDE\\DiskAMDX_HARDDISK___________________________2.5+____\\5&2770a7af&0&0.0.0_0-{05901221-D566-11d1-B2F0-00A0C9062910}"
               },
               {
                  "value":"LowDateTime:-445445610,HighDateTime:30778799***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\intelppm.sys[PROCESSORWMI]"
               },
               {
                  "value":"LowDateTime:398767260,HighDateTime:30646967***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\ACPI.sys[ACPIMOFResource]"
               },
               {
                  "value":"LowDateTime:-1637837527,HighDateTime:30762899***Binary mof failed, see WMIPROV.LOG",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\monitor.sys[MonitorWMI]"
               },
               {
                  "value":"LowDateTime:-649833737,HighDateTime:30733938***Binary mof compiled successfully",
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\DREDGE\\%windir%\\system32\\DRIVERS\\mssmbios.sys[MofResource]"
               },
               {
                  "value":"1354301477",
                  "key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\00004109110000000000000000F01FEC\\Usage\\WORDFiles"
               },
               {
                  "value":"1354301536",
                  "key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\00004109110000000000000000F01FEC\\Usage\\ProductFiles"
               },
               {
                  "value":"1354301450",
                  "key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\00004109E60090400000000000F01FEC\\Usage\\ProductNonBootFilesIntl_1033"
               },
               {
                  "value":"01 01 00 00 00 00 00 00 00 00 06 00 00 00",
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Common\\Toolbars\\Settings\\Microsoft Word"
               },
               {
                  "value":"12642",
                  "key":"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\Last Counter"
               },
               {
                  "value":"12643",
                  "key":"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\Last Help"
               },
               {
                  "key":"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\Updating"
               },
               {
                  "value":"SW\\{eeab7790-c514-11d1-b42b-00805fc1270e}\\asyncmac",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{ad498944-762f-11d0-8dcb-00c04fc3358c}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{ad498944-762f-11d0-8dcb-00c04fc3358c}\\DeviceInstance"
               },
               {
                  "value":"1",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\DeviceClasses\\{cac88484-7515-4c03-82e6-71a87abac361}\\##?#SW#{eeab7790-c514-11d1-b42b-00805fc1270e}#asyncmac#{cac88484-7515-4c03-82e6-71a87abac361}\\Control\\ReferenceCount"
               },
               {
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\22\\(Default)"
               },
               {
                  "value":"00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\24\\ffffffffffffffffffffffffffffff00"
               },
               {
                  "value":"00 00 00 00 71 00 00 00 19 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\24\\ffffffffffffffffffffffffffffff01"
               },
               {
                  "value":"01 00 00 00 5A 00 00 00 D6 17 00 00 FF FF FF FF FF FF FF FF FF FF FF FF",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\24\\ffffffffffffffffffffffffffffff02"
               },
               {
                  "value":"00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF",
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\24\\ffffffffffffffffffffffffffffff03"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\ndis.sys[MofResourceName]",
                  "value":"LowDateTime:-1971493113,HighDateTime:30676308***Binary mof failed, see WMIPROV.LOG"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\System32\\Drivers\\portcls.SYS[PortclsMof]",
                  "value":"LowDateTime:-1221632304,HighDateTime:30487028***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\ACPI.sys.mui[ACPIMOFResource]",
                  "value":"LowDateTime:-403062016,HighDateTime:30016570***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\HDAudBus.sys[HDAudioMofName]",
                  "value":"LowDateTime:-1867536076,HighDateTime:30116016***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\System32\\Drivers\\en-US\\portcls.SYS.mui[PortclsMof]",
                  "value":"LowDateTime:-503062016,HighDateTime:30016570***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\advapi32.dll[MofResourceName]",
                  "value":"LowDateTime:-1337772912,HighDateTime:30778796***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\en-US\\advapi32.dll.mui[MofResourceName]",
                  "value":"LowDateTime:-1270310445,HighDateTime:30778796***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\mssmbios.sys.mui[MofResource]",
                  "value":"LowDateTime:-143062016,HighDateTime:30016570***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\en-US\\HDAudBus.sys.mui[HDAudioMofName]",
                  "value":"LowDateTime:-2018029312,HighDateTime:30016571***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\en-US\\ndis.sys.mui[MofResourceName]",
                  "value":"LowDateTime:-1258029312,HighDateTime:30016571***Binary mof failed, see WMIPROV.LOG"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\en-US\\intelppm.sys.mui[PROCESSORWMI]",
                  "value":"LowDateTime:2076937984,HighDateTime:30016571***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\intelppm.sys[PROCESSORWMI]",
                  "value":"LowDateTime:-2085707242,HighDateTime:30778791***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\ACPI.sys[ACPIMOFResource]",
                  "value":"LowDateTime:-1241494372,HighDateTime:30646958***Binary mof compiled successfully"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\DRIVERS\\monitor.sys[MonitorWMI]",
                  "value":"LowDateTime:1016868137,HighDateTime:30762891***Binary mof failed, see WMIPROV.LOG"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\WBEM\\WDM\\%windir%\\system32\\drivers\\mssmbios.sys[MofResource]",
                  "value":"LowDateTime:2004871927,HighDateTime:30733930***Binary mof compiled successfully"
               },
               {
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Security\\Trusted Documents\\LastPurgeTime",
                  "value":"26791636"
               },
               {
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\Data\\Toolbars",
                  "value":"4C 00 00 00 A3 01 00 00 01 00 00 00 02 01 FF FF BD 00 00 00 00 00 00 00 00 00 10 00 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 01 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 01 02 01 FE 00 00 00 00 00 00 00 00 1E 00 58 00 5C 01 58 00 1B 00 00 00 01 00 E2 71"
               },
               {
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation\\ActiveTimeBias",
                  "value":"4294967176"
               },
               {
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup\\BITS_LOG",
                  "value":"%windir%\\System32\\Bits.log"
               },
               {
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup\\BITS_BAK",
                  "value":"%windir%\\System32\\Bits.bak"
               },
               {
                  "key":"HKU\\S-1-5-21-575823232-3065301323-1442773979-1000\\Software\\Microsoft\\Office\\14.0\\Word\\MTTT",
                  "value":"34 06 00 00 A0 C2 86 8C 98 32 D6 01 00 00 00 00 80 0A 00 00 E0 A7 FF B1 98 32 D6 01 00 00 00 00"
               },
               {
                  "key":"HKLM\\SOFTWARE\\Microsoft\\WBEM\\PROVIDERS\\Performance\\Performance Data",
                  "value":"28 1B 00 00 01 00 00 00 00 00 00 00 10 00 00 00 18 1B 00 00 09 00 00 00 9A 00 00 00 01 00 00 00 01 00 00 00 40 00 00 00 1A 00 00 00 5C 00 5C 00 2E 00 5C 00 72 00 6F 00 6F 00 74 00 5C 00 77 00 6D 00 69 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 01 00 00 04 00 00 00 08 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 64 00 00 00 68 00 00 00 3A 00 00 00 4D 00 53 00 69 00 53 00 43 00 53 00 49 00 5F 00 43 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 69 00 6F 00 6E 00 53 00 74 00 61 00 74 00 69 00 73 00 74 00 69 00 63 00 73 00 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 00 1A 00 00 00 49 00 6E 00 73 00 74 00 61 00 6E 00 63 00 65 00 4E 00 61 00 6D 00 65 00 00 00 2F 20 4D 6F 64 75 6C 65 20 4E 61 6D 65 3A 48 00 00 00 00 00 00 00 02 00 00 00 15 00 00 00 00 00 00 00 64 00 00 00 00 05 41 10 48 00 00 00 1C 00 00 00 42 00 79 00 74 00 65 00 73 00 52 00 65 00 63 00 65 00 69 00 76 00 65 00 64 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 04 00 00 00 15 00 00 00 00 00 00 00 64 00 00 00 00 05 41 10 40 00 00 00 14 00 00 00 42 0 .. truncated"
               },
               {
                  "key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\00004109E60090400000000000F01FEC\\Usage\\ProductNonBootFilesIntl_1033",
                  "value":"1367932938"
               },
               {
                  "key":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS\\StateIndex",
                  "value":"1"
               },
               {
                  "key":"HKLM\\SYSTEM\\ControlSet001\\Control\\Nsi\\{eb004a03-9b1a-11d4-9123-0050047759bc}\\24\\ffffffffffffffffffffffffffffff01",
                  "value":"00 00 00 00 6D 00 00 00 19 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF"
               }
            ],
            "has_pcap":false,
            "processes_tree":[
               {
                  "process_id":"2936",
                  "name":"%windir%\\system32\\wbem\\wmiprvse.exe"
               },
               {
                  "process_id":"2900",
                  "name":"wmiadap.exe /F /T /R"
               },
               {
                  "process_id":"2644",
                  "name":"\"%ProgramFiles(x86)%\\Microsoft Office\\Office14\\WINWORD.EXE\" %SAMPLEPATH%"
               },
               {
                  "process_id":"2256",
                  "name":"%windir%\\System32\\svchost.exe -k WerSvcGroup"
               }
            ],
            "analysis_date":1607472788,
            "processes_terminated":[
               "wmiadap.exe /F /T /R",
               "%windir%\\System32\\svchost.exe -k WerSvcGroup"
            ],
            "has_html_report":false,
            "registry_keys_deleted":[
               "HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\First Counter",
               "HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Last Counter",
               "HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\First Help",
               "HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Last Help",
               "HKLM\\SYSTEM\\ControlSet001\\Services\\WmiApRpl\\Performance\\Object List"
            ],
            "behash":"fd7358c7e7f4d2d645756a08e2f519ec",
            "last_modification_date":1607584657,
            "sandbox_name":"C2AE"
         },
         "type":"file_behaviour",
         "id":"e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c_C2AE",
         "links":{
            "self":"https://www.virustotal.com/api/v3/file_behaviours/e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c_C2AE"
         }
      },
      {
         "attributes":{
            "verdicts":[
               "MALWARE"
            ],
            "ip_traffic":[
               {
                  "destination_ip":"224.0.0.22"
               },
               {
                  "transport_layer_protocol":"UDP",
                  "destination_ip":"224.0.0.252",
                  "destination_port":5355
               }
            ],
            "files_written":[
               "C:\\Users\\user\\AppData\\Local\\Temp\\b5514e47d2abe363e158aa892fa0dbe4.docx",
               "C:\\Users\\user\\AppData\\Local\\Temp\\~$514e47d2abe363e158aa892fa0dbe4.docx"
            ],
            "modules_loaded":[
               "UxTheme",
               "OLEAUT32",
               "ole32",
               "msctf",
               "IMM32",
               "api-ms-win-downlevel-advapi32-l2-1-0",
               "ADVAPI32",
               "usp10",
               "dwrite",
               "SXS",
               "MSCTF"
            ],
            "has_pcap":true,
            "analysis_date":1607514315,
            "sandbox_name":"Yomi Hunter",
            "has_html_report":true,
            "behash":"30c9e987f1b060915e2d4a531489b650",
            "last_modification_date":1607541972,
            "ids_alerts":[
               {
                  "rule_category":"Potentially Bad Traffic",
                  "alert_severity":"medium",
                  "alert_context":{
                     "src_ip":"10.10.0.121",
                     "dest_ip":"224.0.0.22"
                  },
                  "rule_msg":"DECODE_IP_OPTION_SET",
                  "rule_source":"snort",
                  "rule_id":"444"
               },
               {
                  "rule_category":"Attempted Information Leak",
                  "alert_severity":"medium",
                  "alert_context":{
                     "src_ip":"10.10.0.121",
                     "protocol":"UDP",
                     "dest_ip":"224.0.0.252",
                     "src_port":51706,
                     "dest_port":5355
                  },
                  "rule_msg":"PSNG_UDP_PORTSWEEP_FILTERED",
                  "rule_source":"snort",
                  "rule_id":"23"
               }
            ],
            "processes_created":[
               "C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding",
               "C:\\Program Files (x86)\\Microsoft Office\\Office12\\WINWORD.EXE /Automation -Embedding",
               "C:\\Windows\\splwow64.exe 12288",
               "bin\\is32bit.exe -f C:\\Program Files (x86)\\Microsoft Office\\Office15\\WINWORD.EXE",
               "bin\\GLIHZOHpN.exe --app C:\\Program Files (x86)\\Microsoft Office\\Office15\\WINWORD.EXE --only-start --args C:\\Users\\A4148~1.MON\\AppData\\Local\\Temp\\b5514e47d2abe363e158aa892fa0dbe4.docx /e --curdir C:\\Users\\A4148~1.MON\\AppData\\Local\\Temp",
               "C:\\Program Files (x86)\\Microsoft Office\\Office15\\WINWORD.EXE C:\\Users\\A4148~1.MON\\AppData\\Local\\Temp\\b5514e47d2abe363e158aa892fa0dbe4.docx /e",
               "bin\\is32bit.exe -p 1884"
            ],
            "processes_tree":[
               {
                  "process_id":"1884",
                  "time_offset":24909,
                  "name":"63ca65483996721f7e5de56cb5036d32.EXE"
               }
            ],
            "files_opened":[
               "C:\\",
               "C:\\Users\\",
               "C:\\Users\\user\\",
               "C:\\Users\\user\\AppData\\",
               "C:\\Users\\user\\AppData\\Local\\",
               "C:\\Users\\user\\AppData\\Local\\Temp\\b5514e47d2abe363e158aa892fa0dbe4.docx",
               "C:\\Users\\user\\AppData\\Local\\Temp\\~$514e47d2abe363e158aa892fa0dbe4.docx",
               "C:\\Windows\\Fonts\\staticcache.dat"
            ]
         },
         "type":"file_behaviour",
         "id":"e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c_Yomi Hunter",
         "links":{
            "self":"https://www.virustotal.com/api/v3/file_behaviours/e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c_Yomi Hunter"
         }
      }
   ],
   "links":{
      "self":"https://www.virustotal.com/api/v3/files/e8a2b27a55533d19b8c1b6d5af8f7988bfad771b9debb9a6c1903625a457065c/behaviours?limit=10"
   }
}
  ```
  
  #### Download VirusTotal - Comments
  ```bash
  python3 VirusTotal_v3_comments.py --file b553641092e1a15e70f1229cb9ada0a47132f054
  ```
  #### Download AlienVault - Static & Dynamic
  ```bash
  python3 AlienVault_analysis.py --file b553641092e1a15e70f1229cb9ada0a47132f054
  ```


## Requirements
- Python 3.7 and higher
- Internet Connection (Proxy Support; SSL/TLS interception can be a problem)



## Get the API Keys

### Virustotal
1. Create an account here [https://www.virustotal.com/#/join-us](https://www.virustotal.com/#/join-us)
2. Check `Profile > My API key` for your public API key

### OTX AlienVault
1. Create an account here [https://otx.alienvault.com/] (https://otx.alienvault.com/)
2. Check `API Integration` here [https://otx.alienvault.com/api] (https://otx.alienvault.com/api)
