---
layout: post
title: Vulnerabilities found in VMWare by me
---
This post is going to be about the two vulnerabilities found by me in the VMWare hypervisor during my internship at quarkslab, it was a great experience in which I learned a lot.

I found these two vulnerabilities in the Cortado ThinPrint virtual printing component, specifically in the fonts.


## Architecture and how the virtual printing component works
First a brief explanation of the architecture of the virtual printing component
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

This vulnerability is found in the parsers for the **EMRI_ENGINE_FONT** records and for **EMRI_TYPE1_FONT**, I chose **TYPE1** to show the vulnerability.

first let's look at the **EMRI_TYPE1_FONT** record.

![config](/images/vmtuto3.png)

The vulnerability is that we can send a negative **FileEndOffs** value. I sent -1 to check and this is an error because the field description says that it only accepts unsigned integers.

In the poc we send the value -1 which will be FileEndOffs as the image shows.
![config](/images/vmtuto10.png)


We see the verification:


![config](/images/vmtuto4.png)

``` c
if ( FileEndOffs + pFontType1Init > pEndFontType1 )
```
Add the pointer to the beginning of where the font file begins with **FileEndOffs** so that sum will be less than the end pointer of the font because it is a signed check so it will successfully pass that check and later it will use the FileEndOffs field as size in the **realloc** function, which will generate an error and followed by a denial of service.

![config](/images/vmtuto5.png)

We can see here how the realloc function takes the size in esi which is **0xFFFFFFFF** and uses it to reallocar followed by that giving an error and generating a denial of service.

The vulnerability was reported and vmware assigned a CVE which is the following https://www.vmware.com/security/advisories/VMSA-2022-0002.html

## VMWare Workstation Out-of-bounds read vulnerability in the Cortado ThinPrint component TTC Parser (CVE-2021-21987)

I found this vulnerability in the **TCC Header**, first let's explain a little where this header comes from, this appears on the Fileformat.com page

**What is a TTC file?**
The TTC is abbreviated as TrueType Collection is an extension of True Type format. A TTC file can combine the multiple font files into it. These files are beneficial for combining multiple fonts that share many glyphs in common. Before Windows 2000, the TTC files were used in Chinese, Japanese, and Korean versions of windows but later on the support were available for all regions.

**The Structure of Font Collection File**
A TTC file consists of a TTC Header table, Table Directories, and multiple OpenType tables. The TTC Header must be found at the start of the file. A complete table directory for each font must be existed. The TableDirectory format should be similar as existed in a non-collection file. The table counts in all directories within a TTC file are calculated from the start of a TTC file. The tables in a TTC file are referenced through the table directory of their respective fonts. A few of the OpenType tables must appear multiple times, once for each font added in the TTC. Whereas the other tables may be shared by multiple fonts in the TTC file.

**TTC Header**

Two versions of the TTC Header table are available so far:

    Version 1.0 is used for TTC files without digital signatures.
    Version 2.0 can be used for TTC files with or without digital signatures. Here are the TTC Header tables of both versions:
![config](/images/vmtuto6.png)


The vulnerability is in the **tableDirectoryOffsets** field, because the function reads the content of the **tableDirectoryOffsets** field, if we edit the tableDirectoryOffsets field of the **TTF** font header and put A's then it will throw an error.


We edit the font and write **A's**

![config](/images/vmtuto9.png)

This is the vulnerable function:

![config](/images/vmtuto7.png)

We see that we edit our font and write **A's** in the **tableDirectoryOffsets** field and then the function will want to read the content of **0x41414141** so a crash will be generated.

![config](/images/vmtuto8.png)



This vulnerability is the first of the two that I found and I reported it to vmware, but they told me that it had been reported a few weeks ago by another person, so after a while I looked to see who found it first and it is someone who He calls houjingyi233 on his github, I name him to give the credits to him.

