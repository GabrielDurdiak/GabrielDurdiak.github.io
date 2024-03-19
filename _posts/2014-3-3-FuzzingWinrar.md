---
layout: post
title: Fuzzing WinRAR 7zip library
---


As the title says, we are going to fuzz the **7zip format** of winrar, where all the methods and functions used by the 7zip format are found in the dll **7zxa.dll**.

The fuzzer that we are going to use is WinAFL, the first step we have to do is create a harness with the functionalities that we want to test.

The harness has to be designed as follows:

-First open the file.
-Run the functions.
-Close the file and free memory.

To be able to put it together we first have to apply reversing and see how it works, so we choose the functions to fuzz.

I clarify that in this tutorial I am not going to get too deeply into the reversing part but rather I am going to give a screenshot of how it works.

Well, the first method that the 7zip library executes is the CreateObject where the 7zip object will be created and then use its vtable methods to work with the file.

![config](/images/imagen1.png)


This method basically returns the pointer to the 7zip object

Then the open method of your vtable is executed, which is what will open the file and verify its header and other things.

![config](/images/imagen2.png)


