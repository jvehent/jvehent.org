---
layout: post
author: Julien Vehent
title: Starting a Cloud Detection and Response program
excerpt_separator: <!--more-->
---

Now that we've all moved to Cloud, or at least are in the process of doing so, a lot of organizations are trying to modernize
their internal D&R programs to leverage all the shiny capabilities that come with an infrastructure control plane and fully
managed services. For many organizations, however, that initial onboarding boils down to shoehorning traditional programs and
capabilities into their cloud environments which, while viable in the short term, misses on a lot of powerful capabilities.

Cloud Detection & Response being my bread and butter these days, I thought it might be discuss a few of the areas of modernization
one should consider when building out their Cloud D&R program. This is by no means an exhaustive list, and I might write future
posts on the topic should this one prove helpful.

In this post, we will cover:

- Understanding the role of IAM and audit logs
- Preparing an asset inventory
- Identifying and gaining access to internal enrichment sources
- Understand workload ephemerality and how that impacts response

<!--more-->

## The central role of Identity and Access Management

IAM is absolutely central to Cloud D&R. It's the single most important aspect of detecting threats in cloud environments,
and where response efforts will often start.

At a very simplistic leve, the IAM layer is comparable to the network perimeters we used to set around datacenters and offices
in the old days, in the sense that the vast majority of interactions between components of the platform needs to traverse the
IAM layer, and therefore can be blocked, introspected or recorded there.

An application hosted on a virtual machine may use a service account to retrieve a file from storage, or push a message to a queue,
or access a configuration secret, etc. A continuous deployment pipeline may push a new version of a container to a kubernetes cluster
and sping down the previous release. An engineer may need to take a snapshot of a system for backup, or to duplicate that system
elsewhere. All of these interactions go through the IAM layer and leave a trace in the Audit logs of the platform. In AWS, that's
called CloudTrail. In GCP, Cloud Audit Logs.

IAM audit logs are extensive, verbose and incredibly diverse because they need to store the details of hundreds of actions with
thousands of variables. They are typically API driven, such that one API call to the cloud platform will result in one audit logs.
But since most actions require dozens if not hundreds of API calls, it's very easy to have to reassemble large amounts of logs to
get a picture of what actions were taken at a point in time.

One of the very first thing a security team should do when building out a Cloud D&R program is to familiarize themselves with the
audit logs provided by the cloud platform. It is essential to understand what they cover and don't cover, where they are stored,
and how to query them. I cannot overstate enough that you will not be able to improve these skills in the middle of an incident.
Audit logs are too complex, too verbose and too large for someone unfamiliar with them to perform on-the-fly forensics while dealing
with the stress of a potential compromise.

Moreover, audit logs are where a successful dete
