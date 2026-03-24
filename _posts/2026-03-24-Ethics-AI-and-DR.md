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

Aristotle, in the Eudemian Ethics, talks about how character virtues (courage, temperance, justice) are not innate but must be acquired through habituation and practice until they become core to someone's personality. The same hold true for the AIs we design: they must understand nuance and practice their virtues until those become core to their personalities.

Another powerful idea is John Rawls’s Veil of Ignorance, a thought experiment in moral philosophy designed to determine the principles of a just society by asking people to make decisions without knowing their own future status, including their race, income, gender, or abilities. It aims to eliminate personal bias, promoting fairness and equity. Can we ask the AIs we build to design security surveillance systems that would be responsible for monitoring them, without telling the AIs which roles they would hold in this environment?

And to continue on the hypotheticals, what is the probability that we are training a future Ender, who in the 1985 novel by Orson Scott Card, committed genocide by playing a game without being told the consequences of winning, and the impact his actions had on an entire species? For those who haven't read the books, Ender then spends millenia attempting to redeem himself, and as much as the journey make the ~~man~~AI, I for one would prefer to skip to the end on this one.

Ultimately, the consequence we should be aiming for is that systems we build are better able to support society and humans, and protect the planet we live on. And that can only be done if the AIs understand the good and the bad, and recognizes that mistakes are legitimate, often expected, and not necessarily a sign that something or someone is actively malicious.

In practice, this means the "personalities" we give our decision-making AIs need to be balanced. They should err on the side of seeing the better aspects of human nature, rather than being trained only on the negative and dark sides of our peers.
