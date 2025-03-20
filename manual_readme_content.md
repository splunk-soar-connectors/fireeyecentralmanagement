### On-Poll Configuration

For the on-poll product filter asset configuration, optionally provide a comma separated list of
products to include during polling. If not set, all alerts are ingested. Possible Values:

- EX
- NX
- AX

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the FireEye Central Management server.
Below are the default ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |
