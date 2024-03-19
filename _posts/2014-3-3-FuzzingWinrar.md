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


The fourth argument of this OPEN function will be a pointer to some pointers that point to winrar.exe functions, the 3rd argument is a pointer to 0x100000, the second argument will be a pointer to winrar functions that those functions will be used to work on the file later since they are Readfile, Setfilepointer, etc. 

Also this argument contains our the HFile of our file.

![config](/images/imagen3.png)

This is the image of argument 2.

And as the first argument is the pointer to our 7zip Object.

Our harness looks like this:

![config](/images/imagen4.png)

This is the elaboration of createObject, as we see I open the file with CreateFile because that is how winrar opens it

Now to create argument 2 of the open function, the pointer p_functions_winrar_TrabajaConArchivo that contains the pointers to the functions ReadFIle, Setfilepointer, etc. must be reprogrammed in our harness, because you might wonder?

Because to access these functions in the harness you have to load winrar.exe with Loadlibrary and this function does not initialize ReadFile and other functions, so we have to reprogram it.

![config](/images/imagen5.png)

This is ReadFile and I created a structure with each function and sent it to it as an argument.

![config](/images/imagen6.png)

The open function looked like this.

![config](/images/imagen7.png)

Then I call two more methods of the Vtable 7zip, which are method8 and method6, which are roughly functions that prepare the 7zip object to later send it to the extraction function, but I did not do the extraction function because a function had to be reprogrammed. too complex and speaking with Boken he told me that it was not necessary, the main thing is that it sends the open function because that is where it checks the header and other things.

![config](/images/imagen8.png)



