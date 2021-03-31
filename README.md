# Online search hashes-based on VirusTotal-OTX
The Python Scripts to use for downloading static, dynamic analysis and comments from VirusTotal and OTX Alienvault

## Usage
  #### Download VirusTotal - Static Analysis 
  ```bash
  python3 VirusTotal_static_analysis.py --file b553641092e1a15e70f1229cb9ada0a47132f054
   ```
  
  #### Download VirusTotal - Dynamic Analysis
  ```bash
  python3 VirusTotal_dynamic_analysis.py --file b553641092e1a15e70f1229cb9ada0a47132f054
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
