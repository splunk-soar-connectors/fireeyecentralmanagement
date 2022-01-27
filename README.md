[comment]: # "Auto-generated SOAR connector documentation"
# FireEye Central Management

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: FireEye  
Product Name: FireEye CM  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app provides investigative actions for FireEye Central Management

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2022 Splunk Inc."
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
### On-Poll Configuration

For the on-poll product filter asset configuration, optionally provide a comma separated list of
products to include during polling. If not set, all alerts are ingested. Possible Values:

-   EX
-   NX
-   AX

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the FireEye Central Management server.
Below are the default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a FireEye CM asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server\_url** |  required  | string | CM Server URL
**username** |  required  | string | CM Username
**password** |  required  | password | CM Password
**client\_token** |  optional  | password | CM Client Token
**verify\_ssl** |  optional  | boolean | Verify SSL Certificate
**product\_filter** |  optional  | string | On\-Poll Product Filter \(comma\-separated\)
**include\_riskware** |  optional  | boolean | On\-Poll Include Riskware

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Ingest alerts from CM  
[list quarantined emails](#action-list-quarantined-emails) - Retrieves information about quarantined emails  
[get quarantined email](#action-get-quarantined-email) - Save an individual quarantined email to vault  
[get alert](#action-get-alert) - Retrive details about an individual alert  
[list alerts](#action-list-alerts) - Retrieve alerts based on provided filters  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Ingest alerts from CM

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_id** |  optional  | Parameter ignored in this app | string | 
**container\_count** |  optional  | Maximum containers to create | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'list quarantined emails'
Retrieves information about quarantined emails

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Start Time | string | 
**end\_time** |  optional  | End Time | string | 
**from** |  optional  | From | string | 
**subject** |  optional  | Subject | string | 
**appliance\_id** |  optional  | Appliance ID | string |  `fireeye cm appliance id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.from | string | 
action\_result\.parameter\.subject | string | 
action\_result\.parameter\.appliance\_id | string |  `fireeye cm appliance id` 
action\_result\.data\.\*\.email\_uuid | string |  `fireeye cm email uuid` 
action\_result\.data\.\*\.queue\_id | string |  `fireeye cm email queue` 
action\_result\.data\.\*\.message\_id | string | 
action\_result\.data\.\*\.completed\_at | string | 
action\_result\.data\.\*\.from | string | 
action\_result\.data\.\*\.subject | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get quarantined email'
Save an individual quarantined email to vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**queue\_id** |  required  | Queue ID of the quarantined email | string |  `fireeye cm email queue` 
**sensor\_name** |  required  | The sensor display name | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.queue\_id | string |  `fireeye cm email queue` 
action\_result\.parameter\.sensor\_name | string | 
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alert'
Retrive details about an individual alert

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID / UUID of the alert to retrieve | string |  `fireeye cm alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.id | string |  `fireeye cm alert id` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
action\_result\.summary | string | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.id | string |  `fireeye cm alert id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.occurred | string | 
action\_result\.data\.\*\.applianceId | string |  `fireeye cm appliance id` 
action\_result\.data\.\*\.attackDate | string | 
action\_result\.data\.\*\.product | string | 
action\_result\.data\.\*\.malicious | string |   

## action: 'list alerts'
Retrieve alerts based on provided filters

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Specifies the start time of the search\. This filter is used with the duration filter and cannot be specified with an end\_time filter at the same time | string | 
**end\_time** |  optional  | Specifies the end time of the search\. This filter is used with the duration filter and cannot be specified with an start\_time filter at the same time | string | 
**duration** |  required  | Specifies the time interval to search | string | 
**info\_level** |  required  | Specifies the level of information to be returned | string | 
**callback\_domain** |  optional  | Filter for alerts that include callbacks to the specified domain | string |  `domain` 
**file\_name** |  optional  | Filter for alerts with a malware file with a given name | string |  `file name` 
**malware\_name** |  optional  | Filter for alerts with a malware with a given name | string | 
**malware\_type** |  optional  | Filter for alerts with a malware with a given type | string | 
**md5** |  optional  | Filter for alerts with a given md5 hash | string |  `md5`  `hash` 
**recipient\_email** |  optional  | Filter for alerts with a given recipient email | string |  `email` 
**sender\_email** |  optional  | Filter for alerts with a given sender email | string |  `email` 
**src\_ip** |  optional  | Filter for alerts with a given source ip | string |  `ip` 
**dst\_ip** |  optional  | Filter for alerts with a given destination ip | string |  `ip` 
**url** |  optional  | Filter for alerts with a given url | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.duration | string | 
action\_result\.parameter\.info\_level | string | 
action\_result\.parameter\.callback\_domain | string |  `domain` 
action\_result\.parameter\.file\_name | string |  `file name` 
action\_result\.parameter\.malware\_name | string | 
action\_result\.parameter\.malware\_type | string | 
action\_result\.parameter\.md5 | string |  `md5`  `hash` 
action\_result\.parameter\.recipient\_email | string |  `email` 
action\_result\.parameter\.sender\_email | string |  `email` 
action\_result\.parameter\.src\_ip | string |  `ip` 
action\_result\.parameter\.dst\_ip | string |  `ip` 
action\_result\.parameter\.url | string |  `url` 
action\_result\.status | string | 
action\_result\.data\.\*\.id | string |  `fireeye cm alert id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.occurred | string | 
action\_result\.data\.\*\.applianceId | string |  `fireeye cm appliance id` 
action\_result\.data\.\*\.attackDate | string | 
action\_result\.data\.\*\.product | string | 
action\_result\.data\.\*\.malicious | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 