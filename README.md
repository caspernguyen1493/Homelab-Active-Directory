# Homelab-Active-Directory
## About project
This lab is dedicated to learning about AD and stimulating some attacks against AD. Utilizing The Cyber Mentor's guide on Youtube, I will use VMs to stimulate the system, the threat and victim machines. The attack machine will use mostly use Impacket library and mimikatz to achieve the exploit.

The Cyber Mentor's guide: https://youtu.be/VXxH4n684HE?si=9GsGTobiPd9hLfCS

## References & Guides used in this project:
https://youtu.be/VXxH4n684HE?si=9GsGTobiPd9hLfCS
https://viblo.asia/p/leo-thang-dac-quyen-ngang-tren-active-directory-GyZJZdjNVjm#_12-kerberoasting-tren-kerberos-6
https://attackersmindset.com/2021/10/20/detections-that-work-1/

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
|Account|Admin Privilege|
|---|:---:|
| Frank Castle | ✅ |
| Jenny Smith | ❌ |
| SQL Service | ✅ |

## Pass the password / Pass the hash
Pass-the-password (Ptp) uses stolen passwords (which may be obtained via phishing, weak passwords, etc.) to log into machines on the network and move laterally if the compromised account has active sessions on other machines.

Pass-the-hash (Pth) leverages the NTLM hash to authenticate to other machines or services on the network without knowing the original plaintext password. Because Windows supports SSO and uses the NTLMv2 protocol’s challenge/response mechanism, an attacker who obtains a hash can generate a valid response to a server challenge and be accepted as the account owner.

First, I will demonstrate Pass-the-password technique by using Frank Castle credential. It shows that I can PtP over SMB on HOMELAB-ADDC-01

Next, to perform Pass-the-hash, we must know the NTLM hash first. By using secretdump module in Impacket library, we can dump all the credentials on a machine if we have a compromised account. Our target is HOMELAB-PC-01


Let’s try dumping on HOMELAB-PC-02 too

Suppose we don’t know anything about Jenny Smith’s account. On the dumping result above, we can see that we have her NTLM hash. This means we can perform a lateral movement here.
Once again, use crackmapexec to Pth over SMB for both account and we could see that we can Pwned on both machine. 

### *Detection*
There are quite a lot of ways to detect Ptp and Pth. In my homelab, I use EventCode 4624 with Logon Process is NtLmSsp & Login Type is 3. Another type is using Logon Type 9 & Logon Process is seclogo

index="endpoint" source="WinEventLog:Security" EventCode=4624 (Logon_Process=NtLmSsp Logon_Type=3 Account_Name="ANONYMOUS LOGON") OR (Logon_Type=9 Logon_Process=seclogo)



### Kerberoasting

Besides NTLM, AD also uses Kerberos to authenticate. Kerberos uses a more complex and secure mechanism than NTLM, so it addresses many weaknesses in NTLM such as no MFA support, passwords stored on the DC are not salted, weak encryption algorithms, etc.

However, it still suffers from some specific vulnerabilities, and Kerberoasting is one of them.

Kerberoasting process:

Enumerate Service Principal Names (SPNs) → Request Ticket-Granting Service (TGS) tickets → Extract and dump the service ticket → Brute-force the ticket.

In short, it leverages legitimate user activity: because users must request TGS tickets to access internal services, attackers can request or capture those service tickets and perform offline brute-force cracking against the extracted hashes.

So, just like the process above, we will need SPNs first and request TGS ticket. This is can be done with GetUserSPNs module in Impacket

We got the hash! Now bring this to your tool to crack. I am using hashcat with mode 13100 here 



Wait for some times, depending on how strong your machine is. And voila! We have our password.

### *Detection*
It can be difficult to identify Kerberoasting attacks. One of solution is to track down SPN request, if an account request too many services at the same time, it is likely a Kerberoasting attack

Event 4768 (A Kerberos Authentication Ticket [TGT] was Requested) and 4769 (A Kerberos Service Ticket was Requested) will be those need to be looked at first, then if the number of time that the services are requested larger than X (X can be 10, 15, … depend on the monitoring network) we can confirm that is an alert

index=endpoint EventCode IN (4769, 4768) Keywords="Audit Success" NOT Service_Name IN ("*$", "krbtgt")
| stats values(Service_Name) as Unique_Services_Requested dc(Service_Name) as Total_Services_Requested by Account_Name Client_Address _time
| sort 0 - Total_Services_Requested
| where Total_Services_Requested > 10

*(In the picture below, there is not the final line, since I only set up 1 SPN. So if I include it, there will be no result. But in real life scenario, it definitely need that last part)*

## Golden Ticket

Golden Ticket is a Kerberos attack that lets an attacker forge a Ticket Granting Ticket (TGT) by extracting the krbtgt account’s hash (NTHash) and the domain SID. With this information, the attacker can sign a custom PAC (for example granting Domain Admin privileges) and gain broad access across the domain. 

The attack typically begins with initial compromise and privilege escalation to a Domain Admin → retrieve the krbtgt hash by dumping lsass, ntds.dit → forged a “Golden Ticket”, which is a forged Kerberos ticket worked like a valid TGT.

Here is when I use mimikatz to get lsass dump, extract the NThash + SID.

Using this information, I can forge a fake ticket and submit to the current session

### *Detection*

The detection of Golden Ticket can be quite challenging, since this technique is stealthy and can be done offline. A common approach is to check if the kbrtgt’s hash is dumped: DCSync attack, Access to NTDS.dit, lsass.exe on DC

Beside that, we can check 3 event code:
- 4768: A Kerberos authentication ticket (TGT) was requested
- 4769: A Kerberos Service Ticket was requested.
- 4770: A Kerberos service ticket was renewed
Filter user and id, and event that start with 4768 but hasn’t end

index=endpoint EventCode IN (4768, 4769, 4770) 
| rex field=user "(?<username>[^@]+)" 
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)" 
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768) | search NOT user="*$@*" 
| table  _time, ComputerName, username, src_ip_4, service_name, category

