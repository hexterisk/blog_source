---
author:
  name: "hexterisk"
date: 2020-03-09
linktitle: Stack and it's Frames
type:
- post
- posts
title: Stack and it's Frames
tags: ["binary", "symbols", "execution", "path", "constraints", "expression"]
weight: 10
categories: ["basic-binary-analysis"]
---

**Stack** is a data structure, and means exactly what it's name says - a stack(of objects). It is mainly characterized by pushing and popping operations. You push items onto the stack, and then pop those items off. A stack is therefore a **LIFO**(last in, first out) structure. 

Memory for functions, local variables, and flow control is stored in the stack.

### Stack Layout

The stack grows from higher addresses to lower addresses. This behavior can be categorized as _growing downwards_ or _allocation in a top-down manner_. Therefore, top of the stack is actually the lower-most address being used by the stack at that moment.

![why do structure's data members memory allocated from lower to ...](/Stack_and_it's_Frames/1Yz9K.gif)
_Stack growing downwards._

Each time a function call is performed, a new **Stack Frame** is generated. A function maintains its own stack frame until it returns, at which time the caller’s stack frame is restored and execution is transferred back to the calling function.

!["stack"](/Stack_and_it's_Frames/image.png)
_Stack Layout (Reversed top-bottom for easy explanation)._

Calling conventions require parameters to be passed on the stack on x86. On x64, most calling conventions pass parameters through registers. For example, on Windows x64, there is only one calling convention and the fi rst four parameters are passed through  On Linux, the fi rst six parameters are passed on .

### Function Calls

When a function is called, the flow of code execution is transferred to a it's memory location. This transfer of flow has to be setup neatly so that if need be(which generally is the case), the current memory location can be returned to without anything going awry.

**Function Prologue** is executed as soon as the function is called. It consists of a few lines of code that are executed right at the beginning of the function that prepares the stack and the registers for use within this function.

**Function Epilogue** is executed when the function tries to return. It consists of a few lines of code that are executed right at the end of the function so as to restore the stack and registers to the state they were in before the function is called.

##### Calling Conventions for x86:

The x86 architecture requires all function arguments to be pushed on the stack before the function is called.

Function Prologue:
```nasm
    push  ebp         ; Save the stack-frame base pointer (of the calling function).
    mov   ebp, esp    ; Set the stack-frame base pointer to the current location on the stack.
    sub   esp, N      ; Grow the stack by N bytes to reserve space for local variables.
```
Function Epilogue:
```nasm
    mov   esp, ebp    ; Put the stack pointer back where it was when this function was called.
    pop   ebp         ; Restore the calling function's stack frame.
    ret               ; Return to the calling function.
```
 The `leave` instruction can be used in place of the first two instructions because it sets `ESP` to equal `EBP` and pops `EBP` off the stack.

##### Calling Conventions for x64:

The x64 architecture requires the first six function arguments to be set in registers in the following order: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, and `R9`; the remaining are pushed on the stack from right to left.

Disclaimer: Windows requires the first four function arguments to be set in registers in the following order: `RCX`, `RDX`, `R8`, and `R9`; the remaining are pushed on the stack from right to left.

Function Prologue:
```nasm
    mov    [rsp + 8], rcx    ; Saves argument register in home-location.
    push   r15               ; Saves the volatile register r15.
    push   r14               ; Saves the volatile register r14.
    push   r13               ; Saves the volatile register r13.
    sub    rsp, N            ; Grow the stack by N bytes to reserve space for local variables.
    lea    r13, 128[rsp]     ; Establish a frame pointer to point 128 bytes into the allocated space.
```
Function Epilogue:
```nasm
    lea   rsp, -128[r13]    ; Frame pointer's value is restored if it was used in the function.
        ; epilogue proper starts here
    add   rsp, N            ; Destroy the stack frame by pointing the stack pointer before the frame.
    pop   r13               ; Restore the volatile register r13.
    pop   r14               ; Restore the volatile register r14.
    pop   r15               ; Restore the volatile register r15.
    ret                     ; Return to the calling function.
```
Disclaimer:

The only differences between the architectures x86 and x64 we are concerned with at the moment are:

*   Calling conventions (discussed above)
*   Names of the registers and their functions (factual, refer to documentations)
*   Address length (x86: 32 bit, x64: 64bit)

Since these differences have been tended to more or less, the following material is in reference to the x86 architecture since it's much more elaborate.

### Flow of Control:

1.  Arguments are placed on the stack using `push` instructions.
2.  The function is called using `call memory_location`. This causes the current instruction address (that is, the contents of the `EIP` register) to be pushed onto the stack. This address will be used to return to the main code when the function is finished. When the function begins, `EIP` is set to _memory\_location_ (the start of the function).
3.  Through the use of a Function Prologue, space is allocated on the stack for local variables and `EBP` (the base pointer) is pushed onto the stack. This is done to save `EBP` for the calling function.
4.  The function performs its work.
5.  Through the use of a Function Epilogue, the stack is restored. `ESP` is adjusted to free the local variables, and `EBP` is restored so that the calling function can address its variables properly.
6.  The function returns by calling the `ret` instruction. This pops the return address off the stack and into `EIP`, so that the program will continue executing from where the original call was made.
7.  The stack is adjusted to remove the arguments that were sent, unless they’ll be used again later.

### Stack and Frame Analysis

!["stack_frame"](/Stack_and_it's_Frames/1_image.png)
_Individual stack frame (notice how addresses go from higher to lower from bottom to top)._

*   `ESP` would point to the top of the stack, which is the memory address `0x12F02C`.
    *   Whenever data is pushed onto the stack, ESP will be decreased. This is because it will grow towards a lower address.
    *   If the instruction `push eax` were executed, `ESP` would be decremented by four and would contain `0x12F028`, and the data contained in `EAX` would be copied to `0x12F028`.
    *   If the instruction `pop eax` were executed, the data at `0x12F028` would be moved into `EAX`, and then `ESP` would be incremented by four.
    *   Mind you, the value still remains there, it's just invalidated by the system since it is now not in use by the stack and is waiting for either to be overwritten or cleared.
*   `EBP` would be set to `0x12F03C` throughout the duration of the function, so that the local variables and arguments can be referenced using it.
*   The arguments that are pushed onto the stack before the call are shown at the bottom of the stack frame.
*   Next, it contains the return address that is put on the stack automatically by the call instruction. The `old EBP` is next on the stack; this is the EBP from the caller’s stack frame.
