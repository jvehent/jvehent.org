---
layout: post
author: Julien Vehent
title: The cost of micro-services complexity
excerpt_separator: <!--more-->
---

It has long been recognized by the security industry that complex systems are impossible to secure, and that pushing for simplicity helps increase trust by reducing assumptions and increasing our ability to audit. This is often captured under the acronym KISS, for "keep it stupid simple", a design principle [popularized by the US Navy](https://en.wikipedia.org/wiki/KISS_principle) back in the 60s. For a long time, we thought the enemy were application monoliths that burden our infrastructure with years of unpatched vulnerabilities.

So we split them up. We took them apart. We created micro-services where each function, each logical component, is its own individual service, designed, developed, operated and monitored in complete isolation from the rest of the infrastructure. And we composed them ad vitam æternam. Want to send an email? Call the rest API of micro-service X. Want to run a batch job? Invoke lambda function Y. Want to update a database entry? Post it to A which sends an event to B consumed by C stored in D transformed by E and inserted by F. We all love micro-services architecture. It’s like watching dominoes fall down. When it works, it’s visceral. It’s when it doesn’t that things get interesting. After nearly a decade of operating them, let me share some downsides and caveats encountered in large-scale production environments.
<!--more-->
# High operational cost

The first problem is operational cost. Even in a devops cloud automated world, each micro-service, serverless or not, needs setup, maintenance and deployment. We never fully got to the holy grail of completely automated everything, so humans are still involved with these things. Perhaps someone sold you on the idea devs could do the ops work on their free time, but let’s face it, that’s a lie, and you need dedicated teams of specialists to run the stuff the right way. And those folks don’t come cheap.

The more services you have, the harder it is to keep up with them. First you’ll start noticing delays in getting new services deployed. A week. Two weeks. A month. What do you mean you need a three months notice to get a new service setup?

Then, it’s the deployments that start to take time. And as a result, services that don’t absolutely need to be deployed, well, aren’t. Soon they’ll become outdated, vulnerable, running on the old version of everything and deploying a new version means a week worth of work to get it back to the current standard.

# QA uncertainty

A second problem is quality assurance. Deploying anything in a micro-services world means verifying everything still works. Got a chain of 10 services? Each one probably has its own dev team, QA specialists, ops people that need to get involved, or at least notified, with every deployment of any service in the chain. I know it’s not supposed to be this way. We’re supposed to have automated QA, integration tests, and synthetic end-to-end monitoring that can confirm that a butterfly flapping its wings in us-west-2 triggers a KPI update on the leadership dashboard. But in the real world, nothing’s ever perfect and things tend to break in mysterious ways all the time. So you warn everybody when you deploy anything, and require each intermediate service to rerun their own QA until the pain of getting 20 people involved with a one-line change really makes you wish you had a monolith.

The alternative is that you don’t get those people involved, because, well, they’re busy, and everything is fine until a minor change goes out, all testing passes, until two days later in a different part of the world someone’s product is badly broken. It takes another 8 hours for them to track it back to your change, another 2 to roll it back, and 4 to test everything by hand. The post-mortem of that incident has 37 invitees, including 4 senior directors. Bonus points if you were on vacation when that happened.

# Huge attack surface

And finally, there’s security. We sure love auditing micro-services, with their tiny codebases that are always neat and clean. We love reviewing their infrastructure too, with those dynamic security groups and clean dataflows and dedicated databases and IAM controlled permissions. There’s a lot of security benefits to micro-services, so we’ve been heavily advocating for them for several years now.

And then, one day, someone gets fed up with having to manage API keys for three dozen services in flat YAML files and suggests to use oauth for service-to-service authentication. Or perhaps Jean-Kevin drank the mTLS Kool-Aid at the FoolNix conference and made a PKI prototype on the flight back (side note: do you know how hard it is to securely run a PKI over 5 or 10 years? It’s hard). Or perhaps compliance mandates that every server, no matter how small, must run a security agent on them.

Even when you keep everything simple, this vast network of tiny services quickly becomes a nightmare to reason about. It’s just too big, and it’s everywhere. Your cross-IAM role assumptions keep you up at night. 73% of services are behind on updates and no one dares touch them. One day, you ask if anyone has a diagram of all the network flows and Jean-Kevin sends you a dot graph he generated using some hacky python. Your browser crashes trying to open it, the damn thing is 158MB of SVG.

Most vulnerabilities happen in the seam of things. API credentials will leak. Firewall will open. Access controls will get mis-managed. The more of them you have, the harder it is to keep it locked down.

# Everything in moderation

I’m not anti micro-services. I do believe they are great, and that you should use them, but, like a good bottle of Lagavulin, in moderation. It’s probably OK to let your monolith do more than one thing, and it’s certainly OK to extract the one functionality that several applications need into a micro-service. We did this with [autograph](https://github.com/mozilla-services/autograph), because it was obvious that handling cryptographic operations should be done by a dedicated micro-service, but we don’t do it for everything. My advice is to wait until at least three services want a given thing before turning it into a micro-service. And if the dependency chain becomes too large, consider going back to a well-managed monolith, because in many cases, it actually is the simpler approach.