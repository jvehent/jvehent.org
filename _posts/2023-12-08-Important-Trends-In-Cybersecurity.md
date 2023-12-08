---
layout: post
author: Julien Vehent
title: Important trends in Cybersecurity
excerpt_separator: <!--more-->
---

_Some observations on how our field is evolving in four distinct areas: security keys, reduction in attack surfaces, regulatory compliance and shifting left,._

<!--more-->

# Security keys

Perhaps the most impactful trend to security posture is the move away from passwords to security keys, which has eliminated an incredibly large attack surface entirely. We have seen again and again that organizations that fully adopt security keys and webauthn can prevent phishing and password stuffing attacks entirely, but a fair amount of skepticism remained on the maturity of security keys and their practical daily use.

This is changing. Most, if not all, tech companies now require security keys internally and have matured the tooling to manage them. Google Workspace and Microsoft 365 have first class support of security keys, making it easy for administrators to issue and manage the keys.

Users are getting more familiar with them too. Back in 2017 or 2018, usability had a lot of rough edge, and caused confusion which led to frustration. Nowadays, tapping a security key to confirm an authentication step is as natural as entering a password. Yubikeys and Google Titan keys are compatible with virtually all device types, and yes that includes smartphones.

At this point, there are no blockers left to adopting security keys broadly in organizations of all sizes, and we should see many smaller companies migrate to security key based authentication in the coming years.

# Reduction in attack surfaces

Security keys contribute significantly to the reduction in attack surface by closing the password stuffing threat entirely.

But more progress is being made beyond just the authentication phase. Operating systems and hosting environments are rapidly reducing attack surfaces, making operators and security administrators lives a whole lot easier.

Workstations are changing rapidly. In a way, we're going several decades back to the days of purpose-built terminals. At Google, Chromebooks are becoming the norm and bring with them a ton of security improvements, along with a very minimalistic attack surface. We are seeing administrators move away from broadly open systems like Windows, MacOS or Linux, and pushing their users toward locked down platform like ChromeOS.

In the future, I expect Microsoft and Apple to further reduce the attack surfaces of their workstations, like ChromeOS has. This will simplify endpoint management significantly, and perhaps at term remove the need for EDR solutions. We're talking years though, don't uninstall your EDR just yet.

On the hosting side, we've evidently benefitted from the Cloud consolidation and its dramatic operational security benefits. What is now evolving is the hosting of workstations in those cloud environments. Instead of running large desktop computers under their desk, many developers now spend their days in the browsers, using cloud-hosted development environments, with dev servers in the Cloud. And since the CI/CD pipelines are already in the Cloud, there is very little need for self-managed desktop workstations anymore, with all the operational benefits implied.

# Regulatory Compliance

Regulatory compliance has matured enormously over the past ten years. Governments now have a clear understanding of cybersecurity challenges and their importance in protecting modern societies, and they have started hiring skilled1 cybersecurity professionals that drive strategic efforts in the right directions.

Organizations like the Cybersecurity and Infrastructure Security Agency (CISA) in the US or Agence nationale de la sécurité des systèmes d'information (ANSSI) in France have helped their respective governments mature their security posture. More importanlty, they have authored guidelines that are actually very good. Organizations of all sizes would do well to pay attention to these guidelines, as they may become regulatory requirements in the near future.

We continue to see misguided regulations that are often driven by political goals more than they are driven by logic, but those are becoming less common and the cybersecurity community has gained global influence to stir regulatory efforts in the right direction. This is a massive change from even just a few years ago and all information security professional should pay close attention to the efforts various governments are undertaking in this space.

# Shifting Left

I would be remiss to close this post without talking about DevSecOps. I released Securing DevOps over five years ago, and with a lot of the content written around 2016-2017, it is starting to show its age. But I am happy to say that a lot of the modern concept we were discussed as a community back then, and that I captured in the book, are now standard practice. 

Shifting Left is perhaps the one concept that has taken the longest time to mature. It's a good idea in theory: put all your tests, including security test, close to the developers in the code review phase, or in the CI/CD pipeline. But achieving it is a lot harder than it sounds. Over the past decade, we have seen virtually every security tool try to run in this fashion, with very mixed success. Many tools are simply too noisy to run during code checks, and developers often get frustrated when they have to wait hours for tests to run.

I think two things are changing: security tools are better at running "on the left side", and developers are more accepting of the practice.

The industry as a whole is adopting shift-left. Every new product that came to market in the past two years has a shift-left first strategy, with a focus on helping developers write secure code by discovering vulnerabilities faster. This is important because it reduces the historical friction between developers and security practitioners. 

As a result, developers are growing accustomed to consuming security findings as a normal part of their day job. Years ago, they'd get frustrated when trying to read a 30 pages DAST report once a quarter (I use to produce those reports). Nowadays, they solve security gaps in near real-time while reviewing and fixing their patches prior to submission. The net benefits are better code and streamlined security processes that reduce the cost of running a security program.

Shift left is now sufficiently mature that we see it directly integrated into developer tooling, not just security tooling. Github, for example, has built-in security checks that will run code analysis, dependency analysis or secret scanning all automatically.

What does that mean for security professionals? A reduced workload, for one, but also a signal that the baseline is now taken care of by default, and that it is our duty to focus on the next generation of problems.

# But, Julien, you didn't talk about AI at all?

and I probably should have. There is a lot of activity in this space, with security teams across tech companies evaluating the impact of the new generations of LLMs on problems we couldn't previously solve. The jury is still out on what will come out of these efforts, so I think it's too early to point them out as active trends in cybersecurity. But if you have the time, interest and most importantly compute resources, then you should give LLMs a try to see if and how they can solve your most ambiguous security problems.
