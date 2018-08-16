Release History
===============

0.0
---

Initial release

Date: Feb 2018

    * Command line based Autofocus queries run serially per hash
    * Used panafapi.py for Autofocus queries


0.1
---

Date: Aug 2018

    * UI to input hashlist, hashtype, and query name values
    * Move to direct queries in python, no panafapi integration
    * Multi-query first stage and individual sig coverage lookups for faster run time
    * Enhanced data fields with malware tags/tag_groups and sig status
    * gettagdata.py to pull complete list of tags and groups from Autofocus
    * Use of query_tag attribute to isolate query runs: unique json output files and filter tag for Kibana
    * Multi-page and type=scan to support large scale input lists and query results


