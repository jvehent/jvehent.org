---
layout: post
author: Julien Vehent
title: Data Driven Detection Engineering
excerpt_separator: <!--more-->
---

_In which I argue for stronger software engineering skills in cybersecurity, and a focus on data engineering._

My initial foray in the world of detection & response occurred in the mid-2000s, when the field of cybersecurity was still nascent and white hats were figuring out how to industrialize defensive techniques. Back then, the job of a security engineer was to deploy intrusion detection systems across the network and write simple rules that would typically match on IP address or signature hashes.

```
alert udp $EXTERNAL_NET 53 -> $HOME_NET any
( msg:"DNS SPOOF query response PTR with TTL of 1 min. and no authority";
  content:"|85 80 00 01 00 01 00 00 00 00|";
  content:"|C0 0C 00 0C 00 01 00 00 00|<|00 0F|";
  classtype:bad-unknown; sid:253; rev:4;
)
```
_an example of snort rule that alerts on suspicious DNS traffic_

Security engineers focused primarily on network infrastructure and threat intelligence. Aggregating IOCs, applying rules to well-placed sensors and investigating alerts was an analyst's primary focus. You'd place tripwires all over the place, and wait for an attacker to trigger an alert.

This seems to have served us well for a long time. We refined it over the years, with more sophisticated alert languages, frameworks like MITRE ATT&CK that helped organize threats, log aggregation systems like Splunk, etc. And judging by the content of most BSides conferences, it is still the go-to approach for a lot of teams out there.

However, my observation over the past five years, first building the threat detection pipeline at Mozilla, then running the Cloud Detection team at Google, is that detection & response has shifted to focus on data driven detection engineering. The future of D&R leverages complex data models using sophisticated pipelines to detect threats in anomalous behaviors. And, as an industry, we're not ready for it.

**Detection Engineering**

While traditional security administrators used their systems and network skills to build layers of threat detection, most modern threat detection systems built today require solid software engineering skills. Panther, a popular threat detection platform with a primary focus on AWS, uses Python for all of its [detection rules](https://github.com/panther-labs/panther-analysis/blob/master/rules/aws_cloudtrail_rules/abnormally_high_event_volume.py). Suricata, the most sophisticated IDS system out there, [adopted Lua](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/rule-lua-scripting.html) to support more complex rules. Back when I wrote Securing Devops, we tried to use a tool called Hindsight to write complex threat detection rules, also in Lua. Simpler rule languages are still being developed and have a lot of value, but even [Chronicle's YARA-L](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview) is inching toward turing-completeness. 

The benefits of these changes are very real, and treating these modern systems as software opens up a world of possibilities. Unit tests, for example, allow detection engineers to iterate quickly on their detection rules without having to wait for logs to flow through test systems. Coding standards facilitate collaborations in large teams, and lead to higher quality. Peer reviews reduce risks and disseminate knowledge. And so on. All the benefits that the field of software engineering have accumulated over the years are transferable detection engineering. But we need security engineers who are trained in software development, a skillset that is still not a fundamental part of the cybersecurity curriculum.

**Data Engineering**

Back in 2017-or-so, we had developed this appetite for software engineering in threat detection, and rebuilt Mozilla's pipeline using a log engine called [Hindsight](https://github.com/mozilla-services/hindsight). Hindsight's Lua engine was powerful and could ingest large volumes of logs in real time while applying complex detection logic.

Once we realized how much we could do with complex detection logics, we pushed further and further. However, Lua is not a practical language that scales well to large codebases, and we quickly ran into the limitations of the platform, and Hindsight's threat detection never really made it to production. Chapter 8 of Securing Devops, Analyzing logs for fraud and attacks, is perhaps the only relic left of that attempt. But we learned a very valuable lesson that opened up a new area for us: data pipelines!

While we were failing at using Hindsight, another team at Mozilla had migrated to Apache Beam and GCP Dataflow. Their primary purpose was processing Firefox's telemetry, but an engineer in my team (Hey Aaron) figured that we could use the exact same tech for threat detection. He built a prototype in Dataflow and demonstrated the value of using a streaming pipeline.

Data streaming pipelines require a minimal amount of data normalization to function efficiently. When old detection systems were content with ascii logs, data pipelines work on normalized data structures that have pre-determined fields and methods, on top of which detection rules can be implemented.
