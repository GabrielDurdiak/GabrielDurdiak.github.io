---
layout: post
title: Fuzzing WinRAR 7zip library
---

# Harness making

As the title says, we are going to fuzz the **7zip format** of winrar, where all the methods and functions used by the 7zip format are found in the dll **7zxa.dll**.

The fuzzer that we are going to use is WinAFL, the first step we have to do is create a harness with the functionalities that we want to test.

The harness has to be designed as follows:

* First open the file.
* Run the functions.
* Close the file and free memory.

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

Then I call two more methods of the Vtable 7zip, which are metodo8 and metodo6, which are roughly functions that prepare the 7zip object to later send it to the extraction function, but I did not do the extraction function because a function had to be reprogrammed. too complex and speaking with Boken he told me that it was not necessary, the main thing is that it sends the open function because that is where it checks the header and other things.

![config](/images/imagen8.png)



Well, first it executes metodo8, its 1st argument is a pointer to the7zip object, the 2nd sends a 13, and the third a pointer to a buffer set to zero.

![config](/images/imagen9.png)

Then execute metodo6, its arguments are the following: the first is the pointer to the7 zip object, the second is zero, the third is a constant that is 3 and the fourth is a pointer to a buffer created with Malloc and set to zero.

![config](/images/imagen10.png)

And finally the close method that releases the 7zip object and in our harness we release the objects that we allocated.

![config](/images/imagen11.png)

After we have our harness ready, we are going to fuzz and try our luck and see what happens.

# Preparing Fuzzing

## Minimization

First we need a corpus of 7zip files and then minimize it with tools from Winafl itself, what is this for?
The minimization of the files means that only the files that generate new paths in the code remain in our corpus, thus we expand the code coverage and we can go further

With winafl-cmin.py we minimize it

```
python winafl-cmin.py --skip-dry-run -D
C:\DynamoRIO-Windows-7.1.0-1\bin32 -t 100000 -i corpus -o C:\result
-coverage_module harness7zip.exe -target_module harness7zip.exe -target_offset
0x1529 -nargs 2 -- harness7zip.exe @@
```
The result folder is where it will return all the files that generate new routes.


After we do this we start fuzzing.


# Running WinAFL

Something to clarify, we are going to use two commands, we are going to parallelize them into two, one master and the other slave, the master is going to take care of deterministic tasks such as bit flips, byte flips and the slave of the dirty and random task.

It is convenient to do this because you will be doing several fuzzing strategies at the same time.

First we execute the master with -M

```
afl-fuzz.exe -i in -o out -M master -D C:\DynamoRIO-Windows-7.1.0-1\bin32 -t 20000 --
-coverage_module harness7zip.exe -fuzz_iterations 5000 -target_module harness 7zip.exe
-target_offset 0x1529 -nargs 2 -- harness 7zip.exe @@

```
In the target_offset we must put the offset where our harness function begins.

And then we execute the slave with -S.

```
afl-fuzz.exe -i in -o out -S Slave01 -D C:\DynamoRIO-Windows-7.1.0-1\bin32 -t 20000 --
-coverage_module harness7zip.exe -fuzz_iterations 5000 -target_module harness 7zip.exe
-target_offset 0x1529 -nargs 2 -- harness 7zip.exe @@
```
We left it fuzzing for a couple of hours and these are the results.



![config](/images/imagen12.png)



