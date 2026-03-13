---
layout: post
author: Julien Vehent
title: Is Living Off The Land the New Zero-Day?
excerpt_separator: <!--more-->
---

I want to come back to the Stryker cyberattack that occurred earlier this week. Stryker, a medical device company, was targeted on Wednesday by a threat actor group associated with the Iranian government, allegedly in retaliation to the offensive conducted by the American and Israeli governments.

The environment itself is a fairly standard corporate setting, powered mostly by Windows devices. What is critical about the attack against Stryker—from both a security strategy and a detection perspective—is that it appears no zero-day exploit, external malware, or any traditional intrusion methods were used to compromise the infrastructure.

Instead, it is hypothesized that Stryker could have been compromised through leaked credentials, granting the attackers access to their internal IT infrastructure (this is not confirmed and I'm not making any statement on ongoing forensics, but it is the publicly discussed hypothesis). The threat actors may have leveraged this access to issue remote wipe and remote factory reset commands to the corporate fleet of Windows machines.

This type of attack is an interesting evolution of threat vectors we have observed over the past decade, particularly in cloud-heavy environments. Intrusions now often rely on what we call "living off the land" attacks. Rather than developing a specific piece of code to compromise the infrastructure, the actors gain access to the standard tooling used by the legitimate administrators and engineers who maintain the environment.

<!--more-->

In the cloud, we see this around the Identity and Access Management (IAM) layers, where leaked service account keys can be stolen and used to further compromise cloud projects. When credentials are not sufficiently protected, attackers can gain access and issue remote commands inside the management infrastructure.

From a detection and response standpoint, we traditionally focus on protecting corporate environments through host-based heuristics like developing malware signatures, tripwires, or trying to identify indicators of compromise such as file modifications and suspicious network connections.

However, in environments heavily dependent on identity and access management, where attackers can effectively replicate the activity of legitimate administrators by stealing credentials, those traditional detection heuristics are fundamentally insufficient. They fail to provide visibility into the threat actor’s behavior. We are forced to find ways to separate legitimate activity performed by the organization’s members from activity that is anomalous and should be scrutinized.

This separation is extremely hard for two main reasons:
Firstly, very few organizations possess the operational discipline required for threat detection teams to build clear patterns of expected behavior. Administrators frequently use superadmin credentials directly for all sorts of actions, at all times of the day, on all sorts of resources. This makes it nearly impossible to separate a legitimate but noisy administrator from a threat actor.
Secondly, we do not yet have ubiquitous models that allow us to learn, model, and build patterns around the expected behavior of an organization’s administrators. These models are necessary to apply against incoming audit telemetry and effectively detect deviation.
To protect themselves from the type of attack that targeted Stryker, organizations must implement a two-part strategy focused on hardening identities and improving behavioral analysis.

The first step is isolating superadmin credentials into separate identities that are not directly given to members of the organization. These identities should be stored more securely such that elevated access—and preferably multi-party authorization with multiple members signing off on access—is required to leverage them. While these actions can be mundane and happen every day, ensuring these highly sensitive identities require multi-factor authentication and multi-party authorization significantly reduces the risk that a single credential leak will lead to a catastrophic attack.

The second part, from a detection and response perspective, is to leverage that identity separation to focus audit analysis specifically on privileged identities. By looking at logs coming only from those elevated identities, security teams can train models to detect deviations from expected usage patterns. This field is generally called User and Entity Behavior Analysis (UEBA). It is important to understand there are no silver bullets here. UEBA does not work in chaotic environments. If an environment is too noisy, the legitimate administrative activities will generate too many alerts, causing detection and response teams to rapidly silence and ignore the system. Therefore, the foundational step is always to clean up the access controls and access patterns so that UEBA can be applied to clean telemetry, allowing anomalies to be surfaced efficiently.

In summary, first, ensure privileged identities are protected behind multi-factor authentication and multi-party authorization. Second, build detection and response heuristics that specifically analyze these highly privileged accounts and apply malicious activity detection to that telemetry.

