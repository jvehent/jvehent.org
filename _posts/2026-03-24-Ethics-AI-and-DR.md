---
layout: post
author: Julien Vehent
title: Ethics, AI and Detection & Response
excerpt_separator: <!--more-->
---

Deciding how we train artificial intelligence to achieve the positive outcomes we're looking for is an increasing concern. I've been wondering how the fields of Ethics in Philosophy can help us navigate this space, especially when we talk about security, surveillance, and detection and response.

Now, full disclosure: I am no philosophical expert. Quite the opposite, in fact, but I am a curious student of philosophy and an observer of human nature.

It’s clear that LLMs have reached the maturity of producing "intellectual" work products almost faster than humans, for domains that are well studied and where the body of knowledge is well represented in the training datasets. It's also becoming obvious that the very definition of "coding" will evolve: as we move away from using source code as the interface from human to machines, prompts become the better representation of intent. And that’s fine. The shape of the hammer doesn't really matter to the house we're building; the goal is still a livable, welcoming space for our fellow humans.

Instead of focusing solely on the mechanics, I prefer to focus on the **outcomes** we’re aiming for.

<!--more-->

And that’s where things get much less clear. As a society, we’re rightfully concerned about asking AIs to make decisions, but we haven’t fully explored how to tell them how to make those decisions. Security surveillance offers a fascinating case study. We've codified a lot of decision-making into engineering terms. For instance, it’s clearly codified that an employee taking trade secrets to a competitor is unacceptable. We can write code to detect this behavior and escalate it to remediation. But an AI also needs to decide the right course of action when evaluating potential incidents, much like a human uses decades of upbringing and training to apply critical thinking. Here, the **personalities** and character traits we give our AIs are largely undefined.

In fact, when we look at how AI mostly behaves today, they often replicate some of the darker aspects of human nature. They've been trained on how to be crafty and get the job done, sometimes without all the necessary data. This might be a fine trait for a well-intentioned human, but it’s catastrophic for a malicious and omniscient artificial intelligence.

Which is where I think we make the connection to Ethics, as a way to think about the consequences of our decisions, not just the technical mechanics of achieving them.

For example, what is the ultimate consequence we want when surfacing that an exploit is running on a production machine? We want to isolate the system to prevent the attack from spreading—a clear, technical goal. But when discussing an insider threat, the consequence is more nuanced. If the employee was simply forgetful or made an honest mistake, the intention is not immediate termination. It's about a lesson learned, a slap on the wrist, a bit of training, and a return to work. The action taken depends entirely on the criticality of the incident.

So, how do we codify that into an AI?

One temptation is to train AIs on a large corpus of past security incidents and "true positives." But this path carries a risk of devastating bias. It’s like showing a child only the absolute worst things about human society and then asking them what they think of people (remember that scene from The 5th Element when Leeloo learns about war?). Instead, we must show AIs the good and the bad: true positives and false positives, true negatives and false negatives. The AI must understand critical thinking and uncertainty. It needs to understand that the benefit of the doubt is an important notion to extend to human beings, appreciate the consequences of decisions being made, and how those decisions affect real people.

Ultimately, the consequence we should be aiming for is that systems we build are better able to support society and humans. And that can only be done if the AIs understand the good and the bad, and recognizes that mistakes are legitimate, often expected, and not necessarily a sign that something or someone is actively malicious.

In practice, this means the "personalities" we give our decision-making AIs need to be balanced. They should err on the side of seeing the better aspects of human nature, rather than being trained only on the negative and dark sides of our peers.
