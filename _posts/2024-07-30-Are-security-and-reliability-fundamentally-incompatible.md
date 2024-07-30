---
layout: post
author: Julien Vehent
title: Are security and reliability fundamentally incompatible?
excerpt_separator: <!--more-->
---

I have been meaning to write about the Crowdstrike incident, but it seemed important
to avoid being caught into the chaotic blame game going around. So let’s get this out
of the way first: Yes, Crowdstrike made a
[terrible technical mistake](https://x.com/patrickwardle/status/1817843396628668915)
that they are
ultimately responsible for, but No, they probably didn’t have any other ways to go
about solving their problems for the products they were trying to build. As someone
who has made
[similar mistakes](https://hacks.mozilla.org/2019/05/technical-details-on-the-recent-firefox-add-on-outage/)
in the past, I can understand how they happen, and will
continue to happen. There are no silver bullets, and any sufficiently complicated system
will fail regularly, no matter how much testing, quality assurance, safe coding and
so on that you throw at it.

The question that I am interested in exploring here is whether security is fundamentally
antagonistic to reliability. Will security solutions that are inherently intrusive
inevitably degrade the ability of systems to perform their tasks uninterrupted?
And if yes, are there approaches to reduce that impact to a tolerable minimum?

<!--more-->

Reliability in this context is a broad term. It could represent availability, like in the
case of the Crowdstrike incident, or integrity, as in performing a task free of corruption.

The main issue with reliability in modern systems is that those systems have become so
incredibly complex that it is virtually impossible to predict their behavior. Isolated
systems can be measured to a degree of certainty, using specialized hardware and software,
but common operating systems like the ones our personal computers or cloud infrastructures
are made of are simply too big and with too many moving parts to anticipate how they’ll
behave, and how they’ll crash.

This is essentially what brought the advent of distributed computing to replace the mainframe.
AWS’s main selling point in the early 2010s was that individual systems could, and would,
crash randomly but services would continue to run thanks to their distributed nature.
That never fully worked, and except for a few purposefully designed exceptions, the internet
still mostly runs on monoliths.

From the perspective of a security engineer whose role it is to protect these systems, 
the only viable approach is to always go deeper into the system in order to protect them. 
Back when I was building MIG, it was an intentional design decision to stay above the kernel
and avoid intruding on critical system parts, but that decision limited how much telemetry
the security agents could collect, and increased the risk of a well placed attacker disabling
the agents altogether.

Modern endpoint security agents almost always operate at kernel level now, and use a variety
of tricks to acquire the telemetry they need to perform their security jobs while trying to
remain as lightweight and invisible as possible. But in almost every situation, that requires
leveraging bags of tricks to allow these agents to dig deep into the system.

Those tricks are fundamentally unstable. Some are better than others and rely on actual
frameworks, like Linux’s eBPF which is now an industry standard, but ultimately they all
add potentially unstable code in critical parts of the system that can, and will, make them crash.

Even with the rise of safer programming language (yes, Rust mob at the door, I do hear you),
which in fairness would have prevented the Crowdstrike read-out-of-bounds memory safety error,
the risk of a logic error that cascades into full crash will always exist. And the deeper you
crash, the harder it is to recover from.

So I just don’t think there is any reasonable way to expect our modern, highly sophisticated,
deeply integrated security tooling to always run perfectly, never make any mistake, and never
cause a crash. We have been doing this computer thing for enough decades now to know better.
Security agents will crash, and it’s not entirely fair to blame them for doing so.


Which is where I think the interesting philosophical discussion lies. Should we, as engineers
of this digital world, accept reduced reliability for increased security? Is the tradeoff we
make by building security solutions deeper and deeper into our infrastructure always worth it?

In the middle of the Crowdstrike incident, an IT administrator commented that their entire
hospital’s ER department was offline. And so was their 911 dispatch. It’s easy to assume that
not using Crowdstrike in the first place would have been the wiser choice, but we’ve also seen
ransomware
[take down hospitals](https://apnews.com/article/ransomware-attack-hospitals-emergency-rooms-0841defe1b881b71eccb8826ed46130e)
in recent years, which Crowdstrike would help prevent.
So which one do you pick? The reliability, or the security?

In my role as a security engineer, I have been part of many conversations involving the
potential impact of security agents, positive and negative. On two occasions, infrastructure
teams refused to deploy an agent for reliability reasons. I think one of them was wrong to
do so, but that was many years ago now. The other one, however, was so incredibly right to
refuse that it did save them from a large outage down the road. They had established strict
reliability principles for their services, and flat out refused to run any agent that would
randomly pull data and code from outside their control. Good on them for running a tight ship.

But very few organizations have the maturity to make these type of decisions. I would like to
posit that our industry has made somewhat of a mistake in the past decade. In our push to grow
cybersecurity awareness, we have made most organizations afraid of security risks, to the point
that a lot of organizations will adopt almost any security tool without considering the risk
they are introducing while doing so, including reducing the reliability of their systems.

I do believe that, today and to a degree, security and reliability are incompatible. Security
tooling adds entropy that reduces predictability that reliability depends on. But I think we
could engineer security in a way that doesn’t interfere so much with reliability. Our security
components could be better isolated from running systems, like we do for sidecar containers.
Kernels could improve their telemetry frameworks like eBPF to allow security tooling to access
the data they need without deploying dangerous drivers and modules. etc.

Finally, the need for threat modeling remains important. The CIA triad reminds us that evaluating
Availability is equally important to Integrity and Confidentiality. All three should be considered
before making strategic security decisions. In some cases, that might mean not deploying the
security solutions that puts the reliability of a sensitive system into the hands of a third party.
