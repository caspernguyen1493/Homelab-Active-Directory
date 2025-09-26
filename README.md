# Homelab-Active-Directory
## About project
This lab is dedicated to learning about AD and stimulating some attacks against AD. Utilizing The Cyber Mentor's guide on Youtube, I will use VMs to stimulate the system, the threat and victim machines. The attack machine will use mostly use Impacket library and mimikatz to achieve the exploit.

The Cyber Mentor's guide: https://youtu.be/VXxH4n684HE?si=9GsGTobiPd9hLfCS

## Setup
My setup includes 5 machines. Description down below:
|Name|IP Address|
|---|---|
| HOMELAB-ADDC-01 | 10.40.96.3 |
| HOMELAB-Splunk | 10.40.96.5 |
| HOMELAB-Kali | 10.40.96.6 |
| HOMELAB-PC-01 | 10.40.96.4 |
| HOMELAB-PC-02 | 10.40.96.7 |

And on HOMELAB-ADDC-01, I will create 2 user accounts and 1 service account. For this demo, I am going to use weak passwords for all of these.
