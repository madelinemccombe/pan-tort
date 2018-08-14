## Hash Search as part of the Testing Output Response Toolkit


## Install & start the hash search application
### 1. Clone repo
```git clone https://www.github.com/PaloAltoNetworks/pan-tort.git```
<br/>
### 2. Change into repo directory
```cd pan-tort```
<br/>
### 3. Create python 3.6 virtualenv
```python3.6 -m venv env```
<br/>
### 4. Activate virtualenv
```source env/bin/activate```
<br/>
### 5. Download required libraries
```pip install -r requirements.txt```
<br/>
### 6. Change into hash directory
```cd hash```
<br/>
### 7. Create the af_api.py file with the Autofocus api key
[Create panrc.py](https://github.com/PaloAltoNetworks/pan-tort/wiki/panrc)

### 8. Edit the conf.py file with the hash type used in searches
<br/>

### 9. Create the hash_list.txt file with a list of hashes
[Create hash_list.txt](https://github.com/PaloAltoNetworks/pan-tort/wiki/hash_list)
<br/>
### 10. Run hash_data.py to begin queries and retrieving verdict, filetype, and coverage information
```python hash_data_plus.py```
<br/>
Supported hashtypes are md5, sha1, and sha256
<br/>
### 11. Viewing output json files

* hash_data_pretty.json:  raw data view of per-hash Autofocus responses

* hash_data_estack.json:  raw data output with index to bulk load into ElasticSearch/Kibana for visualization

[ElasticStack Visualization](https://github.com/PaloAltoNetworks/pan-tort/wiki/elasticStack)

NOTE: saved searches, visualizations, and dashboard are in the hash/misc directory for Kibana import
<br/><br/>
## Best Practices and Optional Configuration
You should be all set.  For even more ideas on what you can do with the system and other things that you can download and install to get the most out of pan-tort, checkout the [Wiki](https://github.com/PaloAltoNetworks/pan-tort/wiki/overview)!!