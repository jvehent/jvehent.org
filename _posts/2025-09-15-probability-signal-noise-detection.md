---
layout: post
author: Julien Vehent
title: Probabilities and low signal-to-noise in threat detection
excerpt_separator: <!--more-->
---

tl;dr: probabilistic approach to threat detection, particularly for behavior-based anomalies where traditional deterministic rules struggle, can be used to combine high false-positive signals across a kill chain to reduce overall false positives and provide better investigable context for analysts.

<!--more-->

The standard approach to designing threat detection is to focus on increasing the accuracy of single heuristics to reduce the cost of catching false positives while increasing the likelihood of catching true positives. This approach works well when heuristics are highly deterministic, like process execution tripwires or network-based IOCs (indicators of compromise), and is the original approach used by security teams to implement threat detection. The Yara rule below is an example of this approach used to catch a specific rootkit using deterministic indicators.

```
rule crime_linux_umbreon : rootkit
{
    strings:
        $ = { 75 6e 66 75 63 6b 5f 6c 69 6e 6b 6d 61 70 }
        $ = "unhide.rb" ascii fullword
        $ = "rkit" ascii fullword
    condition:
        uint32(0) == 0x464c457f / Generic ELF header
        and uint8(16) == 0x0003 / Shared object file
        and all of them
}
```

While this approach is still valid in many environments, it starts to break down in behavior-based detections. The problem of User and Entity Behavior Analytics (UEBA) is that the action itself often can be legitimate and permitted by the system, unlike a malicious malware execution, but the overall behavior of the actor performing that action is malicious.

Take, for example, the case of a GCP Service Account performing a policy modification on a role. The action itself is permitted, the API call returns with a success, and the system does not raise any error. From a deterministic detection perspective, there is nothing malicious to anchor on, and the detection team may be tempted to rely on the permitted action itself to trigger an alert. We see this approach used regularly, like in this [AWS IAM Policy modification rule from Panther](https://github.com/panther-labs/panther-analysis/blob/develop/rules/aws_cloudtrail_rules/aws_iam_policy_modified.py), a very good open source detection pipeline. This rule will trigger every time a legitimate policy modification is observed, which is likely to happen dozens or hundreds of times a day in busy environments. 

```
POLICY_CHANGE_EVENTS = {
    "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", “PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion", “AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy",
}
def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in POLICY_CHANGE_EVENTS
```

The very high signal rate of false positives itself is not necessarily the issue; rather, the lack of _investigability_ creates pressure on analysts. Analysts will review these actions out of context and will have no way to determine maliciousness efficiently. They’ll likely have to reach out to the human who either performed the action, or owns the system who performed the action, to ask them to review it. This breaks down in many different ways: the person you’re reaching out to may be out of office, or they may not be the right contact and may have to redirect you, or they may just take a few days to respond, or even worse they may be malicious themselves! So this doesn’t work, and good detection rules must be investigable by the analysts autonomously.

What’s a better approach? We know that we need behavior-based rules that have high false positive rates. And we know that we need context to investigate signals coming from those rules. I’ll argue that looking at these rules in isolation is incorrect, and instead it’s the overall behavior of an actor evaluated both from legitimate activity and potentially malicious signals that we need to look at. 

Let’s go back to Lockheed-Martin’s seven steps Kill Chain: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control (C2), Actions on Objectives. Our goal is to detect the attack at least once in the entire kill chain, preferably in early stages, and definitely before they reach their objective. An attacker will not always hit every single step of the kill chain, but it’s a good enough framework to use in our model. We need three things:
Full context on actions taken by entities. In Cloud platforms, that’s your audit logs.
Signals from high false positive behavior-based rules spread across the kill chain. Those may be “silent” alerts that the detection pipeline can include in likelihood calculations.
Math. Not too much, just high-school probabilities.

Instead of directly triggering alerts to analysts on every signal, we can use combined probabilities to reduce the likelihood of an attacker escaping detection. Let’s take a scenario where the kill chain is covered by 5 detections which have respective false positive rates 95%, 85%, 92%, 94% and 81%. I picked high false positive detection on purpose, because those are the ones you’d generally want to silence out and eventually disable. But if we combine them together, the combined probability of false positive becomes:  P(A and B and C and D) = P(0.95) * P(0.85) * P(0.92) * P(0.94) * P(0.81) = 0.56, or 56%. From very high false positive detections, we end up with a 56% false positive probability, or 44% true positive which is typically impossible to achieve.

Of course, I’m oversimplifying and cheating slightly, because I’m assuming that all five of those detections would fire simultaneously and can be combined effectively, both of which are hard problems to solve. In practice, we would use detection pipelines that are able to query themselves to find “silent” signals to enrich evaluation. There is a lot of data pipeline technological complexity that I’m glossing over. But the point remains: in detection pipelines that have hundreds of rules, one of the best ways to reduce false positive rates is to combine them together.

And this approach also provides analysts with better context to investigate. Paired with surrounding audit logs, they can make the difference between mistakenly closing out a true positive out of repetitive habit, and catching a bad actor. 

What about AI? Could it do this for us? Eventually, but it may take a little while for the existing models to do this well. Today, we can prompt the models to review low quality signals in the context of a log sample and ask for an explanation of behavior. This can help analysts get better context while reviewing findings, but it is not yet able to make automated decisions. Stay tuned though, because this is changing fast…
