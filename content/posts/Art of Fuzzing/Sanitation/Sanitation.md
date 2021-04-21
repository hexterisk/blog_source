---
author:
  name: "hexterisk"
date: 2020-09-16
linktitle: Sanitation
type:
- post
- posts
title: Sanitation
tags: ["sanitizer", "ASan", "MSan", "UBSan", "address-sanitizer", "memory-sanitizer", "undefined-behavior-sanitizer", "TSan", "thread-sanitizer"]
weight: 10
categories: ["art-of-fuzzing"]
---

Sanitation tools, or [sanitizers](https://github.com/google/sanitizers), are a set of libraries that can directly observe and flag an incorrect behavior for a certain class of violation at runtime.

Sanitizers are employed by instrumenting the source code. The compiled binary, therefore, essentially has certain tripwires that catch any invalid or incorrect behavior and reports it. The fact that it only brings about minimal performance overhead allows it to be coupled with fuzzing techniques, a powerful combination.

## Input sanitation

Randomly generated test cases can cause crashes in situations where assumptions were made about the input, and/or proper filtering and cleaning of the input was not implemented.

The assumptions can be of:

*   Data type
    *   For example, implemented integer operations on the input and not filtering out other input types, such as characters.
*   Data length
    *   For example, input longer than the length of the allocated buffer is entered.
*   Data content
    *   For example, Unicode data is provided as input where ASCII is expected.

Such bugs are generally low priority and can be avoided with proper documentation and good programming practices. Therefore, data sanitation is done on the randomly generated test cases to play along with such assumptions so that clean data can enter the application, to explore the more dangerous part.

## Address sanitation

**ASan** detects use-after-frees, buffer overflows and stack-use-after-return.

A shadow memory bitmap is created, where a single bit corresponds to a single byte of the actual memory. Operations corresponding to a memory access are instrumented and the areas neighboring the memory are tainted to check for any changes.

![](/Fuzzing_Sanitation/s.png)
_ASan tainted the bytes surrounding ‘buf’._

ASan is tracking the areas surrounding the buffers (red zones). Since the string being copied into the buffer is longer than the buffer size, some bytes are going to overflow into the surrounding memory areas. The surrounding memory area is invalid in this context, since we only have access to the memory reserved by the buffer. ASan will catch this and throw an error.

## Thread sanitation

**TSan** detects:

*   Using/Calling a lock on _mutex_ without initializing it.
*   Thread leaks, like missing _pthread\_join_.
*   Unsafe calls in signal handlers, like _malloc_.
*   Unlocking from the wrong thread.
*   Data races.

Thread sanitation can be implemented in two ways:

1.  Compile-time Instrumentation involves instrumenting:
    *   All read/write operations.
    *   Function entry/exits.
    *   Atomic operations.
2.  Run-time library:
    *   Replaces _malloc_.
    *   Intercepts thread and synchronization management.
    *   Manages all read/write operations.

## Memory sanitation

**MSAN** detects read operations on uninitialized memory.

A bit-to-bit shadow memory map is created and uninitialized memory is tainted. A secondary shadow map may also be employed to keep track of the origin of a freshly allocated memory and propagated with the uninitialized memory. The origin can later be used to track the fault if an illegal operation on the memory is reported.

Reporting all accesses to uninitialized memory will cause too many alerts. Therefore, errors are only reported on:

*   Conditional branches.
*   De-references.
*   Syscall arguments.

The following operations are allowed (as long as their result is not used):

*   Read.
*   Copy.
*   Mathematical operations.

## Undefined Behavior sanitation

**UBSan** detects any undefined behavior, mainly:

*   Null/Misaligned pointers.
*   Signed integer overflows.
*   Conversion to, from, or between floating-point types which would overflow the destination.

UBSan also checks for:

*   **implicit-conversion**: Checks for suspicious behavior of implicit conversions
*   **integer**: Checks for undefined or suspicious integer behavior (e.g. unsigned integer overflow)
*   **nullability**: Checks for null violation, e.g. passing null as a function parameter, assigning null to an lvalue, or returning null from a function.
*   **local-bounds**: It can catch cases missed by array-bounds.

Citation: [Clang docs](https://clang.llvm.org/docs/index.html).