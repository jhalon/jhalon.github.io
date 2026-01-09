---
layout: single
title: "Reconstructing C++ VTables in Binary Ninja"
date: 2026-01-06
header:
  overlay_image: side-channel.jpg
---

Lately I’ve been spending more time sharpening my static analysis workflow in Binary Ninja, specifically around C++ binaries that lean heavily on virtual functions, inheritance, and opaque class layouts.

As a quick exercise, I decided to poke at a Windows component I was already familiar with and treat it purely as a reverse engineering target. So no deep diving into functionality, just an excuse to learn about reconstructing class layouts and vtables from scratch.

If you’ve ever tried to statically analyze a modern Windows binary compiled with MSVC, you’ve probably run into the same friction points I did, i.e. missing headers, partial or nonexistent symbols, and large chunks of logic hidden behind C++ abstractions like vtables and STL types or COM objects... yuck.

Sure, you can always fall back to WinDbg and trace execution dynamically, but that's not always the most efficient approach. The goal here was to improve my ability to understand what I’m looking at statically by identifying object layouts, name fields, and make the disassembly readable enough that dynamic analysis becomes a a more targeted approach instead of a blind walk.

These (slightly polished...) notes reflect my attempts of reconstructing a C++ class structure and its vtable using Binary Ninja, centered around a single function path I was curious about within Smart Screen, `CheckFileReputation`.

## Initial Code Analysis

I won't dive too deeply into Smart Screen itself, but within the `CheckFileReputation` function, there's a segment of code responsible for initializing a structure that gets used throughout the function. The High Level Intermediate Language (HLIL) representation of that initialization looks like this:

```c
int128_t var_448[0x6]
memset(&var_448, 0, 0x58)
smartscreen::apprep::SmartScreenAppReputation::SmartScreenAppReputation(this: &var_448)
rbx_1.b = *(
    smartscreen::apprep::SmartScreenAppReputation::Initialize(this: &var_448)
    + 0x78)
```

In this snippet, `var_448` is declared as an array of six 128-bit integers (totaling 96 bytes of stack space). It's first cleared with `memset`, then passed as a reference to both the `SmartScreenAppReputation` constructor and the `Initialize` function which sets up the structure for later use in other function calls.

What's interesting here is that the object is being constructed directly on the stack rather than being heap-allocated. This is a common pattern in C++ for RAII (Resource Acquisition Is Initialization), where the object's lifetime is tied to the scope and cleanup happens automatically when the function returns.

Before we dive into reconstructing the class structure, let's talk about vtables a little. If we look into the `SmartScreenAppReputation` constructor function, we see the following snippet of code:

```c
smartscreen::apprep::SmartScreenAppReputation* this_1 = this
*this = &smartscreen::apprep::SmartScreenAppReputation::`vftable'
char arg_10 = 0
std::make_shared<struct std::atomic<bool>, bool>(this + 8)
__builtin_memset(dest: this + 0x18, ch: 0, count: 0x40)
class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > var_a0
int128_t* rax = wp::UUID::Parse(&var_a0)
int128_t var_d8
```

There's more code in this function, but for sake of clarity, we won't focus on the other code.

The very first operation in the constructor is assigning `*this` to the class’s vtable. A [vtable](https://www.learncpp.com/cpp-tutorial/the-virtual-table/) (virtual table) is basically a compiler-generated lookup table of function pointers that allows C++ to resolve virtual calls at runtime.

Each object with virtual functions contains a hidden pointer as its first member. This pointer (called a **vptr** or virtual pointer) points to the class's vtable. When you call a virtual function on an object, the runtime basically follows this chain: object => vptr => vtable => function pointer => actual function code. Initializing the vptr during construction ensures that virtual calls resolve to the correct implementation for the object’s dynamic type.

For our reverse engineering efforts, and to better understand this code statically, we need to figure out how this vtable structure looks and also re-create the initial class structure to better understand the code.

## Reverse Engineering The SmartScreenAppReputation Class

As mentioned earlier, any class with virtual functions will have an associated vtable, but the object itself can also contain concrete data members laid out directly in memory. In this case, `var_448` correspond to the full object layout for the `SmartScreenAppReputation` object.

We know that `var_448` is declared as `int128_t var_448[0x6]`, which gives us 6 × 16 bytes = 96 or `0x60` bytes of total space. The `memset` clears `0x58` (88 bytes), leaving the last 8 bytes untouched. This pointer then gets passed into the `SmartScreenAppReputation` constructor.

Looking at the constructor function, let's trace through what gets initialized. We see that the initial pointer to our `this` object gets set to the `SmartScreenAppReputation` vtable.

```c
smartscreen::apprep::SmartScreenAppReputation* this_1 = this
*this = &smartscreen::apprep::SmartScreenAppReputation::`vftable
```

Next, at offset `0x08`, we store what looks to be shared data which is initiated by [`std::make_shared`](https://en.cppreference.com/w/cpp/memory/shared_ptr/make_shared.html).

```c
std::make_shared<struct std::atomic<bool>, bool>(this + 8)
```

Now here's something that tripped me up. At first I assumed that this function allocates some sort of shared pointer that would be 8 bytes in size, but that's not the case.

So what does `std::make_shared` actually do? Well, it's basically a helper function that creates an object and wraps it in a [`std::shared_ptr`](https://en.cppreference.com/w/cpp/memory/shared_ptr). In this case, it's creating an `std::atomic<bool>`, which is just a thread-safe boolean flag, and setting it up with an initial value of `false`. 

The `atomic<bool>` part means multiple threads can safely read and write to this flag without causing race conditions. This is commonly used for things like [cancellation tokens](https://learn.microsoft.com/en-us/cpp/parallel/concrt/reference/cancellation-token-class?view=msvc-170) where one thread might signal other threads to stop what they're doing.

A `std::shared_ptr` is actually 16 bytes in size on x64, not 8 bytes like you might expect for a pointer. 

The reason is that a `shared_ptr` needs to keep track of more than just where the object is. It needs two pointers - one pointing to the actual object, and another pointing to a "control block" that tracks how many pointers are sharing this object. This control block keeps the reference counts and knows when to actually delete the object (when all the `shared_ptr`s pointing to it are gone). This design lets multiple `shared_ptr` instances safely share ownership of an object without worrying about who's responsible for cleaning it up.

When you call `std::make_shared,` it allocates both the object you want and this control block together in one memory allocation, which is more efficient than allocating them separately. So in memory, we end up with 16 bytes at offset `0x08` - 8 bytes for the pointer to our `atomic<bool>,` and 8 bytes for the pointer to the control block.

```c
template<typename T>
class shared_ptr {
    T* ptr;                    // 8 bytes - pointer to the actual object
    control_block* control;    // 8 bytes - pointer to reference count block
};
// Total: 16 bytes
```

So at offset `0x08`, we have our 16-byte `shared_ptr<std::atomic<bool>>` being constructed. Once the shared pointer is created, we then call a `memset` at offset `0x18` to clear `0x40` (64 bytes) of data, which ends at `0x58` - matching the amount that the initial `memset` cleared. This then just leaves us 8 bytes of unallocated space for the class which ends at 0x60 bytes.

With all this information, we can now map out the complete memory layout for our class. Which will look like so:

```
0x00 - 0x08: VTable pointer (vptr)
0x08 - 0x18: std::shared_ptr<std::atomic<bool>> (16 bytes = 2 pointers)
0x18 - 0x58: Cleared region (0x40 = 64 bytes)
0x58 - 0x60: Reserved/unused (8 bytes)
```

Knowing that, we can now create our initial class structure for `SmartScreenAppReputation`. Which will look like so:

```c
struct SmartScreenAppReputation {
    struct SmartScreenAppReputation_vtable* vftable;   // offset 0x00 (8 bytes)
    int64_t cancelation_token[2];                      // offset 0x08 (16 bytes)
    char padding[0x40];                                // offset 0x18 (64 bytes)
    char reserved[0x8];                                // offset 0x58 (8 bytes)
    // Total: 0x60 (96 bytes) ✓
};
```

I named the `shared_ptr` as `cancelation_token` based on its type `std::atomic<bool>`, which seems to be a pattern for cancellation in multi-threaded code.

> NOTE: Yes, I know there's definitely more going on in that padding region than just empty space. But since we're just focusing on the constructor for this example, this structure is good enough.

Now within Binary Ninja, we can open the **Types** window and press **I** to "Create Types from C Source" and add this structure. Once created, navigate to the `SmartScreenAppReputation` constructor function, highlight the `this` parameter, and press **Y** to change its type to `struct SmartScreenAppReputation*`.

Once done, our code should now look something like this:

```c
struct SmartScreenAppReputation* this_1 = this
this->vftable = &smartscreen::apprep::SmartScreenAppReputation::`vftable'
char arg_10 = 0
std::make_shared<struct std::atomic<bool>, bool>(&this->cancelation_token)
__builtin_memset(dest: &this->padding, ch: 0, count: 0x40)
class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > var_a0
int128_t* rax = wp::UUID::Parse(&var_a0)
int128_t var_d8
```

Much easier to read! Instead of seeing raw offset arithmetic like `this + 8`, we now see named fields like `&this->cancelation_token`.

## Reverse Engineering the VTable Structure

Within our constructor function, we see a pointer to our vtable - `smartscreen::apprep::SmartScreenAppReputation::vftable`. If we navigate to this data address in Binary Ninja, we'll see that the vtable structure isn't properly parsed:

```c
1804a2ab8  struct VTable smartscreen::apprep::SmartScreenAppReputation::`vftable' = 
1804a2ab8  {
1804a2ab8
1804a2ab9  }
```

So how do we fix this? Since Binary Ninja isn't showing us much here, let's look at the raw hex data to see what we're actually working with:

```
1804a2ab0: 65 6d 65 74 72 79 00 00 10 89 2f 80 01 00 00 00  emetry..../.....
1804a2ac0: 90 8a 2f 80 01 00 00 00 90 8c 2f 80 01 00 00 00  ../......./.....
1804a2ad0: f0 65 30 80 01 00 00 00 60 72 30 80 01 00 00 00  .e0.....`r0.....
1804a2ae0: 70 89 2f 80 01 00 00 00 90 bf 2f 80 01 00 00 00  p./......./.....
1804a2af0: c0 bf 2f 80 01 00 00 00 50 71 39 80 01 00 00 00  ../.....Pq9.....
1804a2b00: 50 71 39 80 01 00 00 00 50 71 39 80 01 00 00 00  Pq9.....Pq9.....
1804a2b10: 50 71 39 80 01 00 00 00 61 70 70 6c 69 63 61 74  Pq9.....applicat
1804a2b20: 69 6f 6e 4c 6f 6f 6b 75 70 00 00 00 00 00 00 00  ionLookup.......
```

The vtable starts at offset `0x8` from this dump, which lands us at `0x1804a2ab8`. Now in MSVC, vtables always start with a [virtual destructor](https://www.geeksforgeeks.org/cpp/virtual-destructor/) which is basically the cleanup function that runs when an object is being destroyed.

So if we jump to the address stored at `0x1804a2ab8` (which is `0x000001802f8910` based on the hex dump) in Binary Ninja, we should see the destructor function:

```c
void* __ptr64 
  smartscreen::apprep::SmartScreenAppReputation::`vector deleting destructor'
  (smartscreen::apprep::SmartScreenAppReputation* this, uint32_t arg2)
{
    smartscreen::apprep::SmartScreenAppReputation::~SmartScreenAppReputation(this)
    
    if ((arg2.b & 1) != 0)
        operator delete(this)
    
    return this
}
```

Perfect! We can confirm that this function is indeed the destructor for the `SmartScreenAppReputation` class. The "vector deleting destructor" is just a MSVC thing - it's a compiler generated function that handles both destroying the object and optionally freeing its memory.

Now, looking at the hex data, we can see that the vtable seems to be 96 bytes or `0x60` in size, since it ends right before the string `"applicationLookup"` starts at offset `0x68`.

Let's parse out the function pointers. Since each pointer is 8 bytes on x64, we can count them out:

```
Offset  Address              Notes
------  ----------------     -----
0x00:   0x000001802f8910    Virtual destructor
0x08:   0x000001802f8a90    Function 1
0x10:   0x000001802f8c90    Function 2
0x18:   0x0000018030e5f0    Function 3
0x20:   0x0000018030e760    Function 4
0x28:   0x000001802f8970    Function 5
0x30:   0x000001802fbf90    Function 6
0x38:   0x000001802fbfc0    Function 7
0x40:   0x0000018039e150    Entries 8-11 (all point to same address)
0x48:   0x0000018039e150
0x50:   0x0000018039e150
0x58:   0x0000018039e150
```

One thing we'll notice is that the last 4 pointers all point to the same address: `0x0000018039e150`. If we look at this address, we'll see that it's the `void _purecall() __noreturn` function.

In MSVC, `_purecall()` is a special function that gets called when you try to call a pure virtual function that wasn't implemented. It simply just terminates the program. The presence of these _purecall pointers tells us something interesting - these are pure virtual functions inherited from a base class that `SmartScreenAppReputation` is built on top of. `SmartScreenAppReputation` doesn't provide its own implementations for these functions, leaving them as stubs that just point to `_purecall`.

## Building the VTable Structure

With all 12 entries identified (8 actual functions including the destructor + 4 pure virtual stubs), we can build out our vtable structure like so:

```c
struct SmartScreenAppReputation_vtable {
    void* destructor;                    // offset 0x00
    void* function1;                     // offset 0x08
    void* function2;                     // offset 0x10
    void* function3;                     // offset 0x18
    void* function4;                     // offset 0x20
    void* function5;                     // offset 0x28
    void* function6;                     // offset 0x30
    void* function7;                     // offset 0x38
    void* pure_virtual_stub1;            // offset 0x40
    void* pure_virtual_stub2;            // offset 0x48
    void* pure_virtual_stub3;            // offset 0x50
    void* pure_virtual_stub4;            // offset 0x58
};
```

With our structure defined, we can now apply it in Binary Ninja. Just like before, we create the vtable structure using **Types => Create Types from C Source**, then navigate to the vtable data address (`0x1804a2ab8`) and change its type to `struct SmartScreenAppReputation_vtable`.

Once applied, Binary Ninja will parse the data and show us the actual function names that each pointer references. Like so:

```c
struct SmartScreenAppReputation_vtable smartscreen::apprep::SmartScreenAppReputation::`vftable' = 
{
    void* destructor = smartscreen::apprep::SmartScreenAppReputation::`vector deleting destructor'
    void* function1 = smartscreen::apprep::SmartScreenAppReputation::CheckReputation
    void* function2 = smartscreen::apprep::SmartScreenAppReputation::CheckReputation
    void* function3 = smartscreen::apprep::WindowsAppLookupRequest::ToJson
    void* function4 = smartscreen::apprep::WindowsAppxLookupRequest::ToJson
    void* function5 = smartscreen::apprep::WindowsAppReputationBase::`vector deleting destructor'
    void* function6 = smartscreen::apprep::WindowsAppReputationBase::isFileFromWeb
    void* function7 = smartscreen::apprep::WindowsAppReputationBase::isFileScannedByEdge
    void* pure_virtual_stub1 = _purecall
    void* pure_virtual_stub2 = _purecall
    void* pure_virtual_stub3 = _purecall
    void* pure_virtual_stub4 = _purecall
}
```

Now we have actual function names instead of generic placeholders! Looking at the functions, we can see references to several different classes - `SmartScreenAppReputation`, `WindowsAppLookupRequest`, `WindowsAppxLookupRequest`, and `WindowsAppReputationBase`. These appear to be different components within Smart Screen's reputation checking system, handling different types of scans for regular Windows apps vs Appx packages. The presence of `WindowsAppReputationBase` functions suggests there's some inheritance going on, but the exact class hierarchy would require more analysis to confirm.

## Closing

And that's pretty much it!

Do note, that this post wasn’t about fully understanding the component or chasing a specific bug, but about getting better at reading modern C++ binaries statically. Being able to quickly reconstruct class layouts and vtables like this pays dividends later, especially when you’re trying to reason about complex execution paths without immediately reaching for a debugger.
