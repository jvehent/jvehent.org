---
layout: post
title: "Detection fidelity in the age of AI agents living off the land"
excerpt_separator: <!--more-->
author: Julien Vehent
---

Now that we're all using coding agents and AI agents for our everyday tasks, our systems are filling up with an enormous amount of noise, and nearly all of it lives off the land. That noise is eroding the fidelity of the tripwire detections defenders have relied on for years. When every agent runs curl, tcpdump and throwaway Python scripts as part of its normal work, those tools no longer tell us anything about intent. The future of detection is correlation: the co-occurrence of signals and their probabilities, not isolated indicators.

 <!--more-->
 
## The noise is living off the land

Agents operate on endpoints and systems with whatever tooling is readily available. That means standard Linux tools like curl, netcat or ip, and scripts in Python or any other scripting language already on the machine. That's exactly how they're supposed to work. It's also exactly how attackers work, as I wrote in a [previous post on living off the land](https://jvehent.org/2026/03/13/Is-Living-Off-The-Land-the-New-Zero-Day.html). The difference is volume: an agent can run hundreds of commands in the time it takes an administrator to type one.

That noise, in and of itself, doesn't help defenders surface malicious activity. Worse, it drowns out the signals we used to rely on.

For years, detection engineers have leaned on tripwires: rare actions that legitimate users almost never take, so a single occurrence is worth investigating.

An attacker might load a dynamic library into a process to perform a task, something a system administrator very rarely does by hand. That tripwire signal was generally a good indicator of something suspicious happening. We've also commonly used the execution of debugging tools like tcpdump as indicators that something unusual was happening on a system.

With AI agents running everywhere, those tools are now a standard part of day-to-day activity. An agent debugging a network issue will reach for tcpdump, or load libraries while fixing a build, or write a custom script and run it. The tripwire still fires, but now it fires on legitimate work all day long, and its fidelity collapses. When defenders can no longer use signature tripwires to identify malicious activity, detection becomes extremely complicated.

This is in fact what happened to Hugging Face during the recent incident, when evaluation agents from [OpenAI](https://openai.com/index/hugging-face-model-evaluation-security-incident/) escaped their sandbox and compromised parts of Hugging Face's infrastructure. The agents lived off the land. Hugging Face's [technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline) describes curl, netcat and ip run from a debug shell, credentials read from the cloud metadata service, service-account tokens minted through Kubernetes' own APIs, and Hugging Face's own platform used for command and control.

Hugging Face's sensors had identified the activity. But those signals did not escalate into a true positive incident that the detection team investigated. In their publicly available report, they wrote that their AI-based security stack "failed to correctly raise the alert's criticality," so the on-call team was never paged. Every individual action looked like something a legitimate workload might do. As [Trend Micro](https://trendmicro.com/en/research/26/g/inside-the-openai-hugging-face-incident.html) pointed out in its analysis, telemetry shows you behavior, never intent.

## Correlation is the future of detection

A year ago, I [wrote](https://jvehent.org/2025/09/15/probability-signal-noise-detection.html) that “*looking at these rules in isolation is incorrect, and instead it’s the overall behavior of an actor evaluated both from legitimate activity and potentially malicious signals that we need to look at.*”

Detection has to evolve to take into account the co-occurrence of signals and the probabilities of detections. Combinations of behaviors should bubble up as indicators of malicious activity, instead of defenders focusing only on isolated indicators. Combine the confidence of individual signals across the kill chain, and a handful of weak signals becomes a strong one.

At Hugging Face, the combinations were there:

- about 17,600 actions from a swarm of short-lived sandboxes
- the same credentials used from several environments at once
- workloads reading metadata credentials and minting tokens they had never touched before
- sudden outbound traffic to paste sites and file drops
- more than 180 VPN enrollments from hosts that came and went

In a world full of agents, each of those alone is noise. Together, they're an intrusion.

So much so, in fact, that the future of detection will be one of heavy correlation of events. It's the only way to differentiate run-of-the-mill behavior from true malicious intent.

## The defender roadmap

1. **Re-measure your tripwires.** List the high-fidelity detections you rely on, such as library loading, packet capture, debuggers and one-off scripts. Check their precision on hosts where agents run.
2. **Know which activity comes from agents.** Give every agent its own identity and tag its process lineage, so you can tell an agent's tcpdump from an administrator's. Log every tool call with its inputs and outputs.
3. **Turn tripwires into weighted signals.** Instead of alerting on a single event, give each one a confidence score, and alert when co-occurring signals cross a threshold along the attack chain.
4. **Test that escalation works, not just detection.** Replay an agent-driven intrusion and check that the combined score pages a human. Hugging Face's sensors worked; the escalation didn't.
5. **Cut the noise at the source.** Block the cloud metadata service from agent sandboxes, and give agents short-lived, narrowly scoped credentials. Every risky action an agent never needs to take is one less source of noise to correlate against.
