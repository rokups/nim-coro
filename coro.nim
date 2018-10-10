##
## Copyright (c) 2018 Rokas Kupstys
##
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in
## all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
## THE SOFTWARE.
##

when not nimCoroutines and not defined(nimdoc):
    when defined(noNimCoroutines):
      {.error: "Coroutines can not be used with -d:noNimCoroutines"}
    else:
      {.error: "Coroutines require -d:nimCoroutines".}

import posix, math

proc GC_addStack(bottom: pointer) {.cdecl, importc.}
proc GC_removeStack(bottom: pointer) {.cdecl, importc.}
proc GC_setActiveStack(bottom: pointer) {.cdecl, importc.}

when defined(amd64):
    const platformName = "x86_64"
elif defined(i386):
    const platformName = "i386"
elif defined(arm):
    const platformName = "arm"
elif defined(arm64):
    const platformName = "arm64"
elif defined(powerpc):
    const platformName = "ppc32"
elif defined(powerpc64):
    const platformName = "ppc64"
elif defined(mips):
    const platformName = "mips32"

when defined(windows):
    const abiName = "ms"
elif defined(arm) or defined(arm64):
    const abiName = "aapcs"
elif defined(unix):
    const abiName = "sysv"
    
when defined(windows):
    const executableName = "pe"
elif defined(macosx):
    const executableName = "macho"
elif defined(unix):
    const executableName = "elf"

when defined(windows) and (defined(vcc) or defined(icc)):
    const assemblerName = "masm.asm"
else:
    const assemblerName = "gas.S"

when not declared(platformName) or not declared(abiName) or not declared(executableName) or not declared(assemblerName):
    {.error: "Unsupported platform".}

{.compile: "asm/jump_" & platformName & "_" & abiName & "_" & executableName & "_" & assemblerName.}
{.compile: "asm/make_" & platformName & "_" & abiName & "_" & executableName & "_" & assemblerName.}
{.compile: "asm/ontop_" & platformName & "_" & abiName & "_" & executableName & "_" & assemblerName.}

type CoroContext* = pointer
    ## Saved coroutine context.

type CoroContextTransfer* {.pure.} = object
    ## 
    ctx: CoroContext
    data: pointer

type CoroStack* {.pure.} = object
    stack: pointer
    size: int

type CoroutineEntryPoint = proc (transfer: CoroContextTransfer) {.cdecl.}
type CoroutineTransfer = proc (transfer: CoroContextTransfer): CoroContextTransfer {.cdecl.}

proc jump_fcontext(to: CoroContext, data: pointer=nil): CoroContextTransfer {.importc.}
proc make_fcontext(stack: pointer, size: int, function: CoroutineEntryPoint): CoroContext {.importc.}
proc ontop_fcontext(to: CoroContext, data: pointer, function: CoroutineTransfer): CoroContextTransfer {.importc.}

const recommendedStackSize* = 131072
when defined(windows):
    const
        MEM_RESERVE = 0x2000
        MEM_COMMIT = 0x1000
        MEM_TOP_DOWN = 0x100000
        PAGE_READWRITE = 0x04
        PAGE_GUARD = 0x100

        MEM_DECOMMIT = 0x4000
        MEM_RELEASE = 0x8000

    proc virtualAlloc(lpAddress: pointer, dwSize: int, flAllocationType, flProtect: int32): pointer {.header: "<windows.h>", stdcall, importc: "VirtualAlloc".}
    proc virtualProtect(lpAddress: pointer, dwSize: int, flNewProtect: int32, lpflOldProtect: ptr int32): bool {.header: "<windows.h>", stdcall, importc: "VirtualProtect".}
    proc virtualFree(lpAddress: pointer, dwSize: int, dwFreeType: int32): cint {.header: "<windows.h>", stdcall, importc: "VirtualFree".}

    type SYSTEM_INFO {.final, pure.} = object
        u1: int32
        dwPageSize: int32
        lpMinimumApplicationAddress: pointer
        lpMaximumApplicationAddress: pointer
        dwActiveProcessorMask: ptr int32
        dwNumberOfProcessors: int32
        dwProcessorType: int32
        dwAllocationGranularity: int32
        wProcessorLevel: int16
        wProcessorRevision: int16

    proc GetSystemInfo(lpSystemInfo: var SYSTEM_INFO) {.stdcall, dynlib: "kernel32", importc: "GetSystemInfo".}

    when defined(amd64) or defined(arm64) or defined(powerpc64):
        const minimalStackSize* = 8192
    else:
        const minimalStackSize* = 4096
    proc getPageSize: int =
        var si: SYSTEM_INFO
        GetSystemInfo(si)
        return si.dwPageSize
    proc getMaxSize: int = 1 * 1024 * 1024 * 1024
elif defined(posix):
    when defined(macosx) or defined(bsd):
        const MAP_ANONYMOUS = 0x1000
        const MAP_PRIVATE = 0x02        # Changes are private
    elif defined(solaris):
        const MAP_ANONYMOUS = 0x100
        const MAP_PRIVATE = 0x02        # Changes are private
    elif defined(linux) and defined(amd64):
        # actually, any architecture using asm-generic, but being conservative here,
        # some arches like mips and alpha use different values
        const MAP_ANONYMOUS = 0x20
        const MAP_PRIVATE = 0x02        # Changes are private
    elif defined(haiku):
        const MAP_ANONYMOUS = 0x08
        const MAP_PRIVATE = 0x02
    else:
        var
            MAP_ANONYMOUS {.importc: "MAP_ANONYMOUS", header: "<sys/mman.h>".}: cint
            MAP_PRIVATE {.importc: "MAP_PRIVATE", header: "<sys/mman.h>".}: cint

    const minimalStackSize* = 32768
    proc getPageSize: int = sysconf(30)
    proc getMaxSize: int =
        var limit: RLimit
        discard getrlimit(3, limit)
        return limit.rlim_max
else:
    {.error: "Unsupported platform".}

proc stack_create(needSize: int=0): CoroStack =
    ## Allocates a stack and sets up a guard page. `needSize` should be big enough to contain two pages or more.
    ## If no size is specified then default stack size will be used. It varies by platform.
    var s: CoroStack
    var ssize: int
    var vp, sptr: pointer
    var size = needSize
    if size == 0:
        size = recommendedStackSize
    size = max(size, minimalStackSize)
    var maxSize = getMaxSize();
    if maxSize > 0:
        size = min(size, maxSize)

    var pages = floor(float(size) / float(getPageSize()))
    if pages < 2:
        # at least two pages must fit into stack (one page is guard-page)
        return s

    var size2: int = int(pages * float(getPageSize()))
    assert(size2 != 0 and size != 0)
    assert(size2 <= size)

    when defined(windows):
        vp = virtualAlloc(nil, size2, MEM_COMMIT, PAGE_READWRITE)
        if vp == nil:
            return s

        var old_options: int32
        discard virtualProtect(vp, getPageSize(), PAGE_READWRITE or PAGE_GUARD, addr old_options)
    elif defined(posix):
        vp = mmap(nil, size2, PROT_READ or PROT_WRITE, MAP_PRIVATE or MAP_ANONYMOUS, -1, 0)
        if vp == MAP_FAILED:
            return s
        discard mprotect(vp, getPageSize(), PROT_NONE)
    else:
        vp = c_malloc(size2)
        if vp == nil:
            return s
    
    s.stack = cast[pointer](cast[uint](vp) + cast[uint](size2))
    s.size = size2
    return s

proc stack_destroy(stack: CoroStack) =
    ## Deallocates stack created by `stack_create()`.
    var vp = cast[pointer](cast[uint](stack.stack) - cast[uint](stack.size))
    when defined(windows):
        discard virtualFree(vp, stack.size, MEM_RELEASE)
    elif defined(posix):
        discard munmap(vp, stack.size)
    else:
        c_free(vp)

type Coroutine* {.pure.} = object
    ## A coroutine state.
    stack: CoroStack        ## Coroutine stack.
    ctx: CoroContext        ## Coroutine context.
    prev: CoroContext       ## Coroutine return context.
    entryPoint: proc()      ## Coroutine entry point.
    bottom: pointer         ## A bottom of coroutine stack, set upon coroutine creation.

type CoroRootContext {.pure.} = object
    ## Coroutine execution context of this thread.
    current: ptr Coroutine  ## Current executing coroutine.
    thread: Coroutine       ## Fake coroutine representing main thread.

var coroContext {.threadvar.}: CoroRootContext

proc threadToCoroutine*() =
    ## Initialize coroutines on current thread. Must be called once on a given thread before
    ## first use of any coroutine functions.
    coroContext = CoroRootContext()
    coroContext.thread = Coroutine()
    coroContext.current = addr coroContext.thread

proc entryPointWrapper(t: CoroContextTransfer) {.cdecl.}

proc new*(_: typedesc[Coroutine], entryPoint: proc(), stackSize: int=0): ptr Coroutine =
    ## Allocate a new coroutine and return it.
    var cctx = coroContext
    var stack = stack_create(stackSize)
    var current = cctx.current
    var frame = getFrameState()
    var newCtx = make_fcontext(stack.stack, stack.size, entryPointWrapper)
    var transfer = jump_fcontext(newCtx)
    setFrameState(frame)
    var co = cast[ptr Coroutine](transfer.data)
    cctx.current = current
    co.stack = stack
    co.ctx = transfer.ctx
    co.entryPoint = entryPoint
    return co

proc delete*(self: ptr Coroutine) =
    ## Delete coroutine that is no longer in use. Avoid deleting coroutines that did not exit 
    ## completely as it may lead to memory leaks.
    stack_destroy(self.stack)

proc switch(next: CoroContext, data: pointer=nil): pointer =
    ## Switch to a specified coroutine context.
    var cctx = coroContext
    var self = cctx.current
    GC_setActiveStack(self.bottom)

    var frame = getFrameState()
    var transfer = jump_fcontext(next, data)
    setFrameState(frame)

    GC_setActiveStack(self.bottom)
    self.prev = transfer.ctx
    cctx.current = self
    return transfer.data

proc switch*(next: ptr Coroutine, data: pointer=nil): pointer = switch(next.ctx, data)
    ## Switch to a specified coroutine.

proc entryPointWrapper(t: CoroContextTransfer) {.cdecl.} =
    ## Sets up a coroutine.
    var sp {.volatile.}: pointer
    var cctx = coroContext
    var self = Coroutine(bottom: sp, prev: t.ctx)       # Coroutine object lives on the new stack. No memory allocations here.
    coroContext.current = addr self
    GC_addStack(self.bottom)
    discard switch(self.prev, addr self)                # Switch back to the Coroutine.new() constructor and return address of Coroutine object.
    try:
        self.entryPoint()
    except:
        writeStackTrace()
    GC_removeStack(self.bottom)
    discard switch(self.prev)
    doAssert(false, "Should not execute any more.")
    
when isMainModule:
    var ctx, ctx2: ptr Coroutine

    proc doo() =
        echo "DOO"
    
    proc foo() =
        echo "FOO"
        discard ctx2.switch()
        echo "FOO 2"

    threadToCoroutine()
    ctx = Coroutine.new(foo)
    ctx2 = Coroutine.new(doo)
    
    discard ctx.switch()

    ctx.delete()
    ctx2.delete()

    echo "END"
