---
layout: post
title: Vulnerabilities found by me in VMWare during my internship
---
This post is going to be about the two vulnerabilities found by me in the VMWare hypervisor during my internship at quarkslab, it was a great experience in which I learned a lot.

I found these two vulnerabilities in the Cortado ThinPrint virtual printing component, specifically in the fonts.

first a brief explanation of the architecture of the virtual printing component

The most interesting process is vprintproxy.exe which is started on the host machine and the data is sent from the guest machine through the COM1 port to the vprintproxy.exe process.
The data that is sent does not require any permission so any user can send it and the data is sent in EMFSPOOL format, this format allows other file formats to be attached to records such as sources, images and EMF.



## Denial-of-service vulnerability via Cortado ThinPrint (CVE-2022-22938)

