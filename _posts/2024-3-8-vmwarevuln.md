---
layout: post
title: Vulnerabilities found by me in VMWare during my internship
---
This post is going to be about the two vulnerabilities found by me in the VMWare hypervisor during my internship at quarkslab, it was a great experience in which I learned a lot.

I found these two vulnerabilities in the Cortado ThinPrint virtual printing component, specifically in the fonts.

first a brief explanation of the architecture of the virtual printing component
![config](https://blog.khonggianmang.vn/wp-content/uploads/2020/09/image-2.png)


The most interesting process is **vprintproxy.exe** which is started on the host machine and the data is sent from the guest machine through the **COM1** port to the **vprintproxy.exe** process.
The data that is sent does not require any permission so any user can send it and the data is sent in **EMFSPOOL format**, this format allows other file formats to be attached to records such as fonts, images and EMF.

in the **TPView.dll** dll, it handles records with the TTF, OTF, JPEG2000 formats, so the parsers of the formats of these files are there.
so **EMFSPOOL** contains file format records like TTF, images and more

### Fonts

For source records, TPView.dll supports the full processing of 5 records that EMFSPOOL is available:

EMRI_ENGINE_FONT: Defines a font in TrueType format.
EMRI_TYPE1_FONT: Defines a font in PostScript Type 1 font format.
EMRI_DESIGNVECTOR: Contains the design vector of a font, which characterizes the appearance of a font in 16 properties.
EMRI_SUBSET_FONT - Contains a partial font in TrueType format, with enough glyph outlines for pages up to the current page.
EMRI_DELTA_FONT - Contains new glyphs that will be merged with data from a previous EMRI_SUBSET_FONT record.



## Denial-of-service vulnerability via Cortado ThinPrint (CVE-2022-22938)

