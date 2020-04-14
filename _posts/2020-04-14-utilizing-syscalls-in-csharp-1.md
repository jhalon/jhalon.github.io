---
layout: single
title: "[Red Team Tactics] Utilizing Syscalls in C# - Part 1: Prerequisite Knowledge"
header:
  overlay_image: syscall-bg.jpg
---

Over the past year, the security community - specifically Red Team Operators and Blue Team Defenders - have seen a massive rise in both public and private utilization of [System Calls](https://docs.microsoft.com/en-us/cpp/c-runtime-library/system-calls?view=vs-2019) in windows malware for post-exploitation activities, as well as for the bypassing of [EDR](https://www.crowdstrike.com/epp-101/what-is-endpoint-detection-and-response-edr/) or Endpoint Detection and Response.

Now, to some, the utilization of this technique might seem foreign and brand new, but that's not really the case. Many malware authors, developers, and even game hackers have been utilizing system calls and in memory loading for years. with the initial goal of bypassing certain restrictions and securities put into place by tools such as anti-virus and anti-cheat engines.

A good example of how these syscall techniques can be utilized were presented in a few blog posts, such as - how to [Bypass EDR’s Memory Protection, Introduction to Hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6) by [Hoang Bui](https://twitter.com/SpecialHoang) and the greatest example of them all - [Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR
](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) which initially focused on utilizing syscalls to dump LSASS undetected. As a Red Teamer, the usage of these techniques were critical to covert operations - as it allowed us to carry out post exploitation activities within networks while staying under the radar. 

Implementation of these techniques were mostly done in C++ as to easily interact with the [Win32 API](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) and the system. But, there was always one caveat to writing tools in C++ and that's the fact that when our code compiled, we had an EXE. Now for covert operations to succeed, we as a operators always wanted to avoid having to "touch the disk" - meaning that we didn't want to blindly copy and execute files on the system. What we needed, was to find a way to inject these tools into memory which were more OPSEC (Operational Security) safe. 

While C++ is an amazing language for anything malware related, I seriously started to look at attempting to integrate syscalls into C# as some of my post-exploitation tools began transition toward that direction. This accomplishment became more desirable to me after [FuzzySec](https://twitter.com/FuzzySec) and [The Wover](https://twitter.com/TheRealWover) released their BlueHatIL 2020 talk - [Staying # and Bringing Covert Injection Tradecraft to .NET](https://github.com/FuzzySecurity/BlueHatIL-2020]).

After some painstaking research, failed trial attempts, long sleepless nights, and a lot of coffee - I finally succeed in getting syscalls to work in C#. While the technique itself was beneficial to covert operations, the code itself was somewhat cumbersome - you'll understand why later.

Overall, the point of this blog post series will be to explore how we can use direct system calls in C# by utilizing unmanaged code to bypass EDR and API Hooking. 

But, before we can start writing the code to do that, we must first understand some basics concepts. Such as how system calls work, and some .NET internals - specifically managed vs unmanaged code, P/Invoke, and delegates. Understanding these basics will really help us in understanding how and why our C# code works.

Alright, enough of my ramblings - let's get into the basics!

## Understanding System Calls

In Windows, the process architecture is split between two processor access modes - __user mode__ and __kernel mode__. The idea behind the implementation of these modes was to protect user applications from accessing and modifying any critical OS data. User applications such Chrome, Word, etc. all run in user mode, whereas OS code such as the system services and device drivers all run in kernel mode.

<p align="center"><a href="https://outflank.nl/blog/wp-content/uploads/2019/06/Picture4.png"><img src="https://outflank.nl/blog/wp-content/uploads/2019/06/Picture4.png"></a></p>

The kernel mode specifically refers to a mode of execution in a processor that grants access to __all system memory__ and __all CPU instructions__. Some x86 and x64 processors differentiate between these modes by using another term known as __ring levels__. 

Processors that utilize the ring level privilege mode define four privilege levels - other known as __rings__ - to protect system code and data. An example of these ring levels can be seen below.

<p align="center"><a href="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Priv_rings.svg/1200px-Priv_rings.svg.png"><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Priv_rings.svg/1200px-Priv_rings.svg.png"></a></p>

Within Windows, Windows only utilizes two of these rings - Ring 0 for kernel mode and Ring 3 for user mode. Now, during normal processor operations, the processor will switch between these two modes depending on what type of code is running on the processor. 

So what's the reason behind this "ring level" of security? Well, when you start a user-mode application, windows will create a new process for the application and will provide that application with a private [virtual address space](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces) and a private [handle table](https://flylib.com/books/en/4.419.1.29/1/).

This "__handle table__" is a __kernel object__ that contains [handles](https://docs.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects). Handles are simply an abstract reference value to specific system resources, such as a memory regions or location, an open file, or a pipe. It's initial goal is to hides a real memory address from the API user, thus allowing the system to carry out certain management functions like reorganize physical memory.

Overall, a handles job is to tasks internal structures, such as: Tokens, Processes, Threads, and more. An example of a handle can be seen below.

<p align="center"><a href="/images/win-handles.png"><img src="/images/win-handles.png"></a></p>

Because an applications virtual address space is private, one application can't alter the data that belongs to another application - unless the process makes part of its private address space available as a shared memory section via [file mapping](https://docs.microsoft.com/en-us/windows/win32/memory/file-mapping
) or via the [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect?redirectedfrom=MSDN) function, or unless one process has the right to open another process to use cross-process memory functions, such as [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) and [WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory).

<p align="center"><a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/images/virtualaddressspace01.png"><img src="https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/images/virtualaddressspace01.png"></a></p>

Now, unlike user mode, all the code that runs in kernel mode shares a single virtual address space called __system space__. This means that the kernel-mode drivers are not isolated from other drivers and the operating system itself. So if a driver accidentally writes to the wrong address space or does something malicious, then it can compromise the system or the other drivers. Although there are protections in place to prevent messing with the OS - like [Kernel Patch Protection](https://en.wikipedia.org/wiki/Kernel_Patch_Protection) aka Patch Guard, but let's not worry about these.

Since the kernel houses most of the internal data structures of the operating system (such as the handle tables) anytime a user mode application needs to access these data structures or needs to call an internal Windows routine to carry out a privileged operation (such as reading a file), then it must first switch from user mode to kernel mode. This is where __system calls__ come into play.

For a user application to access these data structures in kernel mode, the process utilizes a special processor instruction trigger called a "__syscall__". This instruction triggers the transition between the processor access modes and allows the processor to access the system service dispatching code in the kernel. This in turn calls the appropriate internal function in [Ntoskrnl.exe](https://en.wikipedia.org/wiki/Ntoskrnl.exe) or __Win32k.sys__ which house the kernel and OS application level logic.

An example of this "switch" can be observed in any application. For example, by utilizing [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) on Notepad - we can view specific Read/Write operation properties and their call stack.

<p align="center"><a href="/images/create-file-switch.jpg"><img src="/images/create-file-switch.jpg"></a></p>

In the image above, we can see the switch from user mode to kernel mode. Notice how the Win32 API [CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) function call follows directly before the Native API [NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) call. 

But, if we pay close attention we will see something odd. Notice how there are two different __NtCreateFile__ function calls. One from the __ntdll.dll__ module and one from the __ntoskrnl.exe__ module. Why is that?

Well, the answer is pretty simple. The __ntdll.dll__ DLL exports the Windows [Native API](https://en.wikipedia.org/wiki/Native_API). These native APIs from ntdll are implemented in ntoskrnl - you can view these as being the "kernel APIs". Ntdll specifically supports functions and system service dispatch stubs that are used for executive functions. 

Simply put, they house the "__syscall__" logic that allows us to transition our processor from user mode to kernel mode!

So how does this syscall CPU instruction actually look like in ntdll? Well, for us to inspect this, we can utilize [WinDBG](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) to disassemble and inspect the call functions in ntdll.

Let's begin by starting WinDBG and opening up a process like notepad or cmd. Once done, in the command window, type the following:

```
x ntdll!NtCreateFile
```

This simply tells WinDBG that we want to __examine__ (x) the __NtCreateFile__ symbol within the loaded __ntdll__ module. After executing the command, you should see the following output.

```
00007ffd`7885cb50 ntdll!NtCreateFile (NtCreateFile)
```

The output provided to us is the memory address of where NtCreateFile is in the loaded process. From here to view the disassembly, type the following command:

```
u 00007ffd`7885cb50
```

This command tells WinDBG that we want to __unassemble__ (u) the instructions at the beginning of the memory range specified. If ran correctly, we should now see the following output.

<p align="center"><a href="/images/create-file-syscall.jpg"><img src="/images/create-file-syscall.jpg"></a></p>

Overall the NtCreateFile function from ntdll is first responsible for setting up the functions call arguments on the stack. Once done, the function then needs to move it's relevant system call number into `eax` as seen by the 2nd instruction `mov eax, 55`. In this case the syscall number for NtWriteFile is 0x55.

Each native function has a specific syscall number. Now these number tend to change every update - so at times it's very hard to keep up with them. But thanks to [j00ru](https://twitter.com/j00ru) from Google Project Zero, he constantly updates his [Windows X86-64 System Call Table](https://j00ru.vexillium.org/syscalls/nt/64/), so you can use that as a reference anytime a new update comes out.

After the syscall number has been moved into `eax`, the __syscall__ instruction is then called. Here is where the CPU will jump into kernel mode and carry out the specified privileged operation. 

To do so it will copy the function calls arguments from the user mode stack into the kernel mode stack. It then executes the kernel version of the function call, which will be [ZwCreateFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile). Once finished, the routine is reversed and all return values will be returned to the user mode application. Our syscall is now complete!

## Using Direct System Calls

Alright, so we know how system calls work, and how they are structured, but now you might be asking yourself... How do we execute these system calls?

It's simple really. For us to directly invoke the system call, we will build the system call using assembly and execute that in our applications memory space! This will allow us to bypass any hooked function that are being monitored by EDR's or Anti-Virus. Of course syscalls can still be monitored and executing syscalls via C# still gives off a few hints - but let's not worry about that as it's not in scope for this blog post.

For example, if we wanted to write a program that utilizes the __NtCreateFile__ syscall, we can build some simple assembly like so:

```asm
mov r10, rcx
mov eax, 0x55 <-- NtCreateFile Syscall Identifier
syscall
ret
```

Alright, so we have the assembly of our syscall... now what? How do we execute it in C#?

Well in C++ this would be as simple as adding this to a new `.asm` file, enabling the [masm](https://docs.microsoft.com/en-us/cpp/assembler/masm/masm-for-x64-ml64-exe?view=vs-2019) build dependency, defining the C function prototype of our assembly, and simply just initialize the variables and structures needed to invoke the syscall.

As easy as that sounds, it's not that simple in C#. Why? Two words - __Managed Code__.

## Understanding C# and the .NET Framework

Before we dive any deeper into understanding what this "__Managed Code__" is and why it's going to cause us headaches - we need to understand what C# is and how it runs on the .NET Framework.

Simply, C# is a type-safe object-oriented language that enables developers to build a variety of secure and robust applications. It's syntax simplifies many of the complexities of C++ and provides powerful features such as nullable types, enumerations, delegates, lambda expressions, and direct memory access. C# also runs on the .NET Framework, which is an integral component of Windows that includes a virtual execution system called the [Common Language Runtime](https://docs.microsoft.com/en-us/dotnet/standard/clr) or CLR and a unified set of class libraries. The CLR is the commercial implementation by Microsoft of the [Common Language Infrastructure](https://en.wikipedia.org/wiki/Common_Language_Infrastructure) known as the CLI.

Source code written in C# is compiled into an [Intermediate Language (IL)](https://docs.microsoft.com/en-us/dotnet/standard/managed-code) that conforms to the CLI specification. The IL code and resources, such as bitmaps and strings, are stored on disk in an executable file called an assembly, typically with an extension of `.exe` or `.dll`.

When a C# program is executed, the assembly is loaded into the CLR, the CLR then performs Just-In-Time (JIT) compilation to convert the IL code to native machine instructions. The CLR also provides other services such automatic [garbage collection](https://docs.microsoft.com/en-us/dotnet/standard/garbage-collection/fundamentals), exception handling, and resource management. Code that's executed by the CLR is sometimes referred to as "__managed code__", in contrast to "__unmanaged code__", which is compiled directly into native machine code for a specific system.

To put it very simply, managed code is just that: code whose execution is managed by a runtime. In this case, the runtime is the **Common Language Runtime**

In therms of unmanaged code, it simply relates to C/C++ and how the programmer is in charge of pretty much everything. The actual program is, essentially, a binary that the operating system loads into memory and starts. Everything else, from memory management to security considerations are a burden of the programmer.

A good visual example of the the .NET Framework is structured and how it compiles C# to IL then to machine code can be seen below.

<p align="center"><a href="https://docs.microsoft.com/en-us/dotnet/csharp/getting-started/media/introduction-to-the-csharp-language-and-the-net-framework/net-architecture-relationships.png"><img src="https://docs.microsoft.com/en-us/dotnet/csharp/getting-started/media/introduction-to-the-csharp-language-and-the-net-framework/net-architecture-relationships.png"></a></p>

Now, if you actually read all that then you would have noticed that I mentioned that the CLR provides other services such as "__garbage collection__".  In the CLR, the garbage collector also known as the __GC__, serves as the automatic memory manager by essentially... you know, "freeing the garbage" that is your used memory. It also gives the benefit by allocating objects on the managed heap, reclaiming objects, clearing memory, and proving memory safety by preventing known memory corruption issues like [Use After Free](https://cwe.mitre.org/data/definitions/416.html). 

Now while C# is a great language, and it provides some amazing features and interoperability with Windows - like in-memory execution and as such - it does have a few caveats and downsides when it comes to coding malware or trying to interact with the system. Some of these issues are:

1. It's easy to disassemble and reverse engineer C# assemblies via tools like [dnSpy](https://github.com/0xd4d/dnSpy) all because they are compiled into IL and not native code.
2. It requires .NET to be present on the system for it to execute.
3. It's harder to do anti-debugging tricks in .NET then in native code.
4. It requires more work and code to interoperate (__interop__) between managed and unmanaged code. 

In case of this blog post, #4 is the one that will cause us the most pain when coding syscalls in C#. Whatever we do in C# is "managed" - so how are we able to efficiently interact with the Windows system and processor? This questions is especially important for us since we want to execute assembly code, and unfortunately for us, there is no inline ASM in C# like there is in C++ with the masm build dependencies.

Well, thankfully for us, Microsoft provided a way for us to be able to do that! And it's all thanks to the CLR! Thanks to how the CLR was constructed, it actually allows us to pass the boundaries between the managed and unmanaged world. This process is known as __interoperability__ or __interop__ for short. With interop, C# supports pointers and the concept of "unsafe" code for those cases in which direct memory access is critical - that would be us! 😉

Overall this means that we can now do the same things C++ can, and we can also utilize the same windows API functions... but, with some <s>major</s> - I mean... minor headaches and inconveniences... heh. 😅

Of course, it is important to note that once the code passes the boundaries of the runtime, the actual management of the execution is again in the hands of unmanaged code, and thus falls under the same restrictions as it would when we code in C++. Thus we need be be careful on how we allocate, deallocate, and manage memory as well as other objects.

So, knowing this, how are we able to enable this interoperability in C#? Well, let me introduce you the person of the hour - [P/Invoke](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) (short for Platform Invoke)!

## Understanding Native Interop via P/Invoke

P/Invoke is a technology that allows you to access structs, callbacks, and functions in unmanaged libraries (meaning DLLs and such) from your managed code. Most of the P/Invoke API that allows this interoperability is contained within two namespaces - specifically [System](https://docs.microsoft.com/en-us/dotnet/api/system?view=netframework-4.8) and [System.Runtime.InteropServices](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices?view=netframework-4.8).

So let's see a simple example. Let's say you wanted to utilize the [MessageBox](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox) function in your C# code - which usually you can't call unless you're building a [UWP](https://docs.microsoft.com/en-us/windows/uwp/get-started/universal-application-platform-guide) app.

For starters, let's create a new `.cs` file and make sure we include the two P/Invoke namespaces.

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
    public static void Main(string[] args)
    {
        // TODO
    }
}
```

Now, let's take a quick look at the C MessageBox syntax that we want to use.

```c
int MessageBox(
  HWND    hWnd,
  LPCTSTR lpText,
  LPCTSTR lpCaption,
  UINT    uType
);
```

Now for starters you must know that the data types in C++ do not match those used in C#. Meaning, that data types such as [HWND](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types) (handle to a window) and [LPCTSTR](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types) (Long Pointer to Constant TCHAR String) are not valid in C#. 

We'll brief over converting these data types for MessageBox now so you get a brief idea - but if you want to learn more then I suggest you go read about the [C# Types and Variables](https://docs.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/types-and-variables).

So for any handle objects related to C++ - such as HWND, the equivalent of that data type (and any pointer in C++) in C# is the [IntPtr Struct](https://docs.microsoft.com/en-us/dotnet/api/system.intptr?view=netframework-4.8) which is a platform-specific type that is used to represent a pointer or a handle.

Any strings or pointer to string data types in C++ can be set to the C# equivalent - which simply is [string](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/strings/). And for UINT or unsigned integer, that stays the same in C#.

Alright, now that we know the different data types, let's go ahead and call the unmanaged MessageBox function in our code.

Our code should now look something like this.

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    public static void Main(string[] args)
    {
        // TODO
    }
}
```

Take note that before we import our unmanaged function, we call the [DllImport](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=netframework-4.8) attribute. This attribute is crucial to add because it tells the runtime that it should load the unmanaged DLL. The string passed in, is the target DLL that we want to load - in this case __user32.dll__ which houses the function logic of MessageBox. 

Additionally, we also specify which [character set](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/charset) to use for marshalling the strings, and also specify that this function calls [SetLastError](https://docs.microsoft.com/en-us/windows/desktop/api/errhandlingapi/nf-errhandlingapi-setlasterror) and that the runtime should capture that error code so the user can retrieve it via [Marshal.GetLastWin32Error()](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getlastwin32error#System_Runtime_InteropServices_Marshal_GetLastWin32Error) to return any errors back to us if the function was to fail.

Finally, you see that we create a private and static MessageBox function with the [extern](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/extern) keyword. This `extern` modifier is used to declare a method that is implemented externally. Simply this tells the runtime that when you invoke this function, the runtime should find it in the DLL specified in `DllImport` attribute - which in our case will be in __user32.dll__.

Once we have all that, we can finally go ahead and call the `MessageBox` function within our main program.

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    public static void Main(string[] args)
    {
        MessageBox(IntPtr.Zero, "Hello from unmanaged code!", "Test!", 0);
    }
}
```

If done correctly, this should now execute a new message box with the title "__Test!__" and a message of "__Hello from unmanaged code!__".

Awesome, so we just learned how to import and invoke unmanaged code from C#! It's actually pretty simple when you look at it... but don't let that fool you!

This was just a simple function - what happens if the function we want to call is a little more complex, such as the [CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) function?

Let's take a quick look at the C syntax for this function.

```c
HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);
```

Let's look at the `dwDesiredAccess` parameter which specifies the access permissions of the file we created by using generic values such as __GENERIC_READ__ and __GENERIC__WRITE__. In C++ we could simply just use these values and the system will know what we mean, but not in C#. 

Upon looking into the documentation we will see that [Generic Access Rights](https://docs.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights) used for the `dwDesiredAccess` parameter use some sort of [Access Mask Format](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format) to specify what privilege we are to give the file. Now since this parameter accepts a [DWORD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/262627d8-3418-4627-9218-4ffe110850b2) which is a 32-bit unsigned integer, we quickly learn that the __GENERIC-*__ constants are actually flags which match the constant to a specific access mask bit value.

In the case of C#, to do the same, we would have to create a new [structure type](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/struct) with the [FLAGS](https://docs.microsoft.com/en-us/dotnet/api/system.flagsattribute?view=netframework-4.8) enumeration attribute that will contain the same constants and values that C++ has for this function to work properly.

Now you might be asking me - where would I get such details? Well the best resource for you to utilize in this case - and any case where you have to deal with unmanaged code in .NET is to use the [PInvoke Wiki](https://www.pinvoke.net/). You'll pretty much find anything and everything that you need here.

If we were to invoke this unmanaged function in C# and have it work properly, a sample of the code would look something like this:

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        EFileAccess dwDesiredAccess,
        EFileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        ECreationDisposition dwCreationDisposition,
        EFileAttributes dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [Flags]
    enum EFileAccess : uint
    {
        Generic_Read = 0x80000000,
        Generic_Write = 0x40000000,
        Generic_Execute = 0x20000000,
        Generic_All = 0x10000000
    }

    public static void Main(string[] args)
    {
        // TODO Code Here for CreateFile
    }
}
```

Now do you see what I meant when I said that utilizing unmanaged code in C# can be cumbersome and inconvenient? Good, so we're on the same page now 😁

Alright, so we've covered a lot of material already. We understand how system calls work, we know how C# and the .NET framework function on a lower level, and we now know how to invoke unmanaged code and Win32 APIs from C#. 

But, we're still missing a critical piece of information. What could that be... 🤔

Oh, that's right! Even though we can call Win32 API functions in C#, we still don't know how to execute our "[native code](https://stackoverflow.com/questions/3434202/what-is-the-difference-between-native-code-machine-code-and-assembly-code)" assembly. 

Well, you know what they say - "If there's a will, then there's a way"! And thanks to C#, even though we can't execute inline assembly like we can in C++, we can do something similar thanks to something lovely called [Delegates](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/)!

## Understanding Delegates and Native Code Callbacks

Can we just stop for a second and actually admire how cool the CLR really is? I mean to manage code, and to allow interop between the GC and the Windows APIs is actually pretty cool.

The runtime is so cool, that it also allows communication to flow in both directions, meaning that you can call back into managed code from native functions by using function pointers! Now, the closest thing to a function pointer in managed code is a [delegate](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/), which is a type that represents references to methods with a particular parameter list and return type. And this is what is used to allow callbacks from native code into managed code.

Simply, delegates are used to pass methods as arguments to other methods. Now the use of this feature is similar to how one would go from managed to unmanaged code. A good example of this can be seen given by Microsoft.

```csharp
using System;
using System.Runtime.InteropServices;

namespace ConsoleApplication1
{
    public static class Program
    {
        // Define a delegate that corresponds to the unmanaged function.
        private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        // Import user32.dll (containing the function we need) and define
        // the method corresponding to the native function.
        [DllImport("user32.dll")]
        private static extern int EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        // Define the implementation of the delegate; here, we simply output the window handle.
        private static bool OutputWindow(IntPtr hwnd, IntPtr lParam)
        {
            Console.WriteLine(hwnd.ToInt64());
            return true;
        }

        public static void Main(string[] args)
        {
            // Invoke the method; note the delegate as a first parameter.
            EnumWindows(OutputWindow, IntPtr.Zero);
        }
    }
}
```

So this code might look a little complex, but trust me - it's not! Before we walk though this example, let's make sure we review the signatures of the unmanaged functions that we need to work with.

As you can see, we are importing the native code function [EnumWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows) which enumerates all top-level windows on the screen by passing the handle to each window, and in turn, passing it to an application-defined callback function.

If we take a peek at the C syntax for the function type we will see the following:

```c
BOOL EnumWindows(
  WNDENUMPROC lpEnumFunc,
  LPARAM      lParam
);
```

If we look at the `lpEnumFunc` parameter in the documentation, we will see that it accepts a pointer to an application-defined callback - which should follow the same structure as the [EnumWindowsProc](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms633498%28v=vs.85%29) callback function. This callback is simply a placeholder name for the application-defined function. Meaning that we can call it anything we want in the application.

If we take a peek at this function C syntax we will see the following.

```c
BOOL CALLBACK EnumWindowsProc(
  _In_ HWND   hwnd,
  _In_ LPARAM lParam
);
```

As you can see this function parameters accept a HWND or pointer to a windows handle, and a LPARAM or Long Pointer. And the return value for this callback is a boolean - either true or false to dictate when enumeration has stopped.

Now, if we look back into our code, on line #9, we define our __delegate__ that matches the signature of the callback from unmanaged code. Since we are doing this in C#, we replaced the C++ pointers with __IntPtr__ - which is the the C# equivalent of pointers.

On lines #13 and #14 we introduce the EnumWindows function from __user32.dll__.

Next on line #17 - 20 we implement the __delegate__. This is where we actually tell C# what we want to do with the data that is returned to us from unmanaged code. Simply here we are saying to just print out the returned values to the console.

And finally, on line #24 we simply call our imported native method and pass our defined and implemented delegate to handle the return data.

Simple!

Alright, so this is pretty cool. And I know... you might be asking me right now - "_Jack, what's this have to do with executing our native assembly code in C#? We still don't know how to accomplish that!_"

And all I have to say for myself is this meme...

<p align="center"><a href="https://beahealthygeek.com/wp-content/uploads/2016/07/patience_grasshopper.jpg"><img src="https://beahealthygeek.com/wp-content/uploads/2016/07/patience_grasshopper.jpg"></a></p>

There's a reason why I wanted to teach you about delegates and native code callbacks before we got here, as delegates are a very important part to what we will cover next. 

Now, we learned that delegates are similar to C++ function pointers, but delegates are fully object-oriented, and unlike C++ pointers to member functions, delegates encapsulate both an object instance and a method. We also know that they allow methods to be passed as parameters and can also be used to define callback methods. 

Since delegates are so well versed in the data they can accept, there's something cool that we can do with all this data. For example, let's say we execute a native windows function such as [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) which allows us to reserve, commit, or change the state of a region of pages in the virtual address space of the calling process. This function will return to us a base address of the allocated region of pages. 

Let's say, for this example we allocated some... oh you know... shellcode per say 😏- see where I'm going with this? No!? Fine... let me explain.

So if we were able to allocate a memory region in our process that contained shellcode and returned that to our __delegate__, then we can utilize something called [type marshaling](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/type-marshaling) to transform incoming data types to cross between managed and native code. This means that we can go from an unmanaged function pointer to a delegate! Meaning that we can execute our assembly or byte array shellcode this way!

So with this general idea, let's jump into this a little deeper!

## Type Marshaling & Unsafe Code and Pointers

As stated before, **Marshaling**  is the process of transforming types when they need to cross between managed and native code. Marshaling is needed because the types in the managed and unmanaged code are different as we've already seen and demonstrated.

By default, the P/Invoke subsystem tries to do type marshaling based on the default behavior, but for those situations where you need extra control with unmanaged code, you can utilize the [Marshal](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal?view=netframework-4.8) class for things like allocating unmanaged memory, copying unmanaged memory blocks, and converting managed to unmanaged types, as well as other miscellaneous methods used when interacting with unmanaged code.

A quick example of how this marshaling works can be seen below.

<p align="center"><a href="https://mark-borg.github.io/img/posts/pinvoke-diagram.png"><img src="https://mark-borg.github.io/img/posts/pinvoke-diagram.png"></a></p>

In our case, and for this blog post, the most important Marshal method will be the  [Marshal.GetDelegateForFunctionPointer](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer?view=netframework-4.8#System_Runtime_InteropServices_Marshal_GetDelegateForFunctionPointer_System_IntPtr_System_Type_) method, which allows us to convert an unmanaged function pointer to a delegate of a specified type.

Now there are a ton of other types you can marshal to and from, and I highly suggest you read up on them as they are a very integral part of the .NET framework and will come in handy whenever you write red team tools, or even defensive tools if you are a defender.

Alright, so we know that we can marshal our memory pointers to delegates - but now the question is, how are we able to create a memory pointer to our assembly data? Well in fact, it's quite easy. We can do some simple pointer arithmetic to get a memory address of our ASM code.

Since C# does not support pointer arithmetic, by default, what we can do is declare a portion of our code to be [unsafe](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/unsafe). This simply denotes an unsafe context, which is required for any operation involving pointers. Overall, this allows us to carry out pointer operations such as doing pointer dereferencing.

Now the only caveat is that to compile unsafe code, you must specify the [`-unsafe`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/unsafe-compiler-option) compiler option. 

So knowing this, let's go over a quick example.

If we wanted to - let's say - execute the syscall for [NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess), what we would do is start by writing the assembly into a byte array like so.

```csharp
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SharpCall
{
    class Syscalls
    {

        static byte[] bNtOpenProcess =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
    }
}
```

Once we have our byte array completed for our syscall, we would then proceed to call the `unsafe` keyword and denote an area of code where unsafe context will occur.

Within that unsafe context, we can do some pointer arithmetic to initialize a new byte pointer called `ptr` and set that to the value of `syscall`, which houses our byte array assembly. As you will see below, we utilize the [fixed](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/fixed-statement) statement, which prevents the garbage collector from relocating a movable variable - or in our case the syscall byte array.

Without a `fixed` context, garbage collection could relocate the variables unpredictably and cause errors later down the line during execution.

Afterwards, we simply cast the byte array pointer into a C# IntPtr called `memoryAddress`. Doing this will allow us to obtain the memory location of where our syscall byte array is located.

From here we can do multiple things like use this memory region in a native API call, or we can pass it to other managed C# functions, or we can even use it in delegates!

An example of what I explained above can be seen below.

```csharp
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SharpCall
{
    class Syscalls
    {
		// NtOpenProcess Syscall ASM
        static byte[] bNtOpenProcess =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtOpenProcess(
            // Fill NtOpenProcess Paramters
            )
        {
            // set byte array of bNtOpenProcess to new byte array called syscall
            byte[] syscall = bNtOpenProcess;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;
                }
            }
        }
    }
}

```

And that about does it! 

We now know how we can take shellcode from a byte array and execute it within our C# application by using unmanaged code, unsafe context, delegates, marshaling and more!

I know this was a lot to cover, and honestly it's a little complex at first - so take your time to read this though and make sure you understand the concepts.

In our next blog post, we will focus on actually writing the code to execute a valid syscall by utilizing everything that we learned here! In addition to writing the code, we'll also go over some concepts to managing your "tools" code and how we can prepare it for future integration between other tools.

Thanks for reading, and stay tuned for Part 2!
