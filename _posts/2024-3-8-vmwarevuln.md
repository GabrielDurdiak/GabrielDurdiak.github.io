---
layout: post
title: Vulnerabilities Found By Me in VMWare During My Internship
---
This post is going to be about the two vulnerabilities found by me in the VMWare hypervisor during my internship at quarkslab, it was a great experience in which I learned a lot.

I found these two vulnerabilities in the Cortado ThinPrint virtual printing component, specifically in the fonts.

first a brief explanation of the architecture of the virtual printing component
![config](/images/vmtuto1.png)


The most interesting process is **vprintproxy.exe** which is started on the host machine and the data is sent from the guest machine through the **COM1** port to the **vprintproxy.exe** process.
The data that is sent does not require any permission so any user can send it and the data is sent in **EMFSPOOL format**, this format allows other file formats to be attached to records such as fonts, images and EMF.

in the **TPView.dll** dll, it handles records with the TTF, OTF, JPEG2000 formats, so the parsers of the formats of these files are there.
so **EMFSPOOL** contains file format records like TTF, images and more

### Fonts

For source records, **TPView.dll** supports the full processing of 5 records that **EMFSPOOL** is available:

- **EMRI_ENGINE_FONT:** Defines a font in TrueType format.
- **EMRI_TYPE1_FONT:**  Defines a font in PostScript Type 1 font format.
- **EMRI_DESIGNVECTOR:** Contains the design vector of a font, which characterizes the appearance of a font in 16 properties.
- **EMRI_SUBSET_FONT:** Contains a partial font in TrueType format, with enough glyph outlines for pages up to the current page.
- **EMRI_DELTA_FONT:** Contains new glyphs that will be merged with data from a previous EMRI_SUBSET_FONT record.

and for example we choose the **EMRI_ENGINE_FONT** registry to search for vulnerabilities, which contains a **TrueType (TTF)** format
  
  ![config](/images/vmtuto.png)

I started reverse and finding the function that processes the **EMRI_ENGINE_FONT** record that contains the TTF format and that is then also parsed.
![config](/images/vmtuto2.png)

In the image we can see that there are the different EMFSPOOL records if, for example, it is of the type EMRI_ENGINE_FONT, the function that parses goes, this type of font is the TTF and the function sends as a parameter the pointer to the EMFSPOOL record and the size of the font TTF

then I started to do the harness, I searched for a large corpus of TTF files and ran WinAFL, but I realized after a while that the fuzzer was running and not discovering new paths, so I started doing reversing manually to see the different paths it took. TTF format for me to edit the files and improve code coverage and discover new paths.

At that moment when I started doing reversing manually I started to find the vulnerabilities without the help of the fuzzer

## Denial-of-service vulnerability via Cortado ThinPrint (CVE-2022-22938)

I found this vulnerability when the **EMRI_ENGINE_FONT** record was parsed, since the **FileSizes** field accepts negative numbers
