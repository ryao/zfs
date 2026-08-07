/**
 * @name Call to `memset` may be deleted
 * @description Using `memset`/`bzero` to clear data that has no subsequent use
 *              can make information-leak vulnerabilities easier to exploit
 *              because the compiler can remove the call (dead-store elimination).
 *              This refined query extends the official `cpp/memset-may-be-deleted`
 *              check (github/codeql#12352) to also cover heap buffers and structure
 *              fields reached through pointers (e.g. OpenZFS gcm_clear_ctx).
 *              This is a revision of the upstream
 *              cpp/memset-may-be-deleted-refined that makes it catch more
 *              issues.
 * @kind problem
 * @id openzfs/refined/cpp/memset-may-be-deleted
 * @problem.severity warning
 * @security-severity 7.8
 * @precision medium
 * @tags security
 *       external/cwe/cwe-014
 */

import cpp
import semmle.code.cpp.dataflow.EscapesTree
import semmle.code.cpp.commons.Exclusions
import semmle.code.cpp.models.interfaces.Alias
import semmle.code.cpp.models.interfaces.Allocation
import semmle.code.cpp.models.interfaces.Deallocation

class MemsetFunction extends Function {
  MemsetFunction() {
    this.hasGlobalOrStdOrBslName("memset")
    or
    this.hasGlobalOrStdName("wmemset")
    or
    this.hasGlobalName(["bzero", "__builtin_memset", "__builtin_bzero"])
  }
}

class SecureMemsetFunction extends Function {
  SecureMemsetFunction() {
    this.hasGlobalOrStdName([
        "memset_s", "explicit_bzero", "explicit_memset", "SecureZeroMemory",
        "RtlSecureZeroMemory", "memzero_explicit"
      ])
    or
    this.hasGlobalName(["explicit_bzero", "explicit_memset", "memzero_explicit"])
  }
}

predicate isNonEscapingArgument(Expr escaped) {
  exists(Call call, AliasFunction aliasFunction, int i |
    aliasFunction = call.getTarget() and
    call.getArgument(i) = escaped.getUnconverted() and
    (
      aliasFunction.parameterNeverEscapes(i)
      or
      aliasFunction.parameterEscapesOnlyViaReturn(i) and
      (call instanceof ExprInVoidContext or call.getConversion*() instanceof BoolConversion)
    )
  )
}

predicate notDisablingBuiltinMemset(FunctionCall call) {
  not exists(Compilation c |
    c.getAFileCompiled() = call.getFile() and
    c.getAnArgument() = "-fno-builtin-memset"
  )
}

// ---------------------------------------------------------------------------
// Case 1: original local-variable pattern (high precision)
// ---------------------------------------------------------------------------
pragma[noinline]
predicate callToMemsetWithRelevantVariable(
  LocalVariable v, VariableAccess acc, FunctionCall call, MemsetFunction memset
) {
  not v.isStatic() and
  not v.getUnspecifiedType() instanceof ReferenceType and
  call.getTarget() = memset and
  acc = v.getAnAccess() and
  variableAddressEscapesTree(acc, call.getArgument(0).getFullyConverted())
}

pragma[noinline]
predicate relevantLocalVariable(LocalVariable v, FunctionCall call, MemsetFunction memset) {
  exists(VariableAccess acc, VariableAccess anotherAcc |
    callToMemsetWithRelevantVariable(v, acc, call, memset) and
    anotherAcc = v.getAnAccess() and
    acc != anotherAcc and
    not anotherAcc.isUnevaluated()
  )
}

predicate localVarMemsetMayBeDeleted(FunctionCall call, string why) {
  exists(LocalVariable v, MemsetFunction memset |
    relevantLocalVariable(v, call, memset) and
    not isFromMacroDefinition(call) and
    forall(Expr escape | variableAddressEscapesTree(v.getAnAccess(), escape) |
      isNonEscapingArgument(escape)
    ) and
    not v.getAnAccess() = call.getASuccessor*() and
    notDisablingBuiltinMemset(call) and
    why = "local variable '" + v.getName() + "'"
  )
}

// ---------------------------------------------------------------------------
// Shared: expression is derived from a variable access (pointer arithmetic /
// field / array / parens / conversions).
// ---------------------------------------------------------------------------
predicate exprFromVariable(Expr e, Variable v) {
  e.getUnconverted() = v.getAnAccess()
  or
  exprFromVariable(e.(ParenthesisExpr).getExpr(), v)
  or
  exprFromVariable(e.getFullyConverted().(Conversion).getExpr(), v)
  or
  exprFromVariable(e.(PointerAddExpr).getLeftOperand(), v)
  or
  exprFromVariable(e.(PointerSubExpr).getLeftOperand(), v)
  or
  exprFromVariable(e.(AddExpr).getAnOperand(), v) and
  e.getUnspecifiedType() instanceof PointerType
  or
  exists(FieldAccess fa |
    fa = e and exprFromVariable(fa.getQualifier(), v)
  )
  or
  exists(AddressOfExpr ao, FieldAccess fa |
    ao = e and fa = ao.getOperand() and exprFromVariable(fa.getQualifier(), v)
  )
  or
  exists(ArrayExpr ae |
    ae = e and exprFromVariable(ae.getArrayBase(), v)
  )
  or
  exists(AddressOfExpr ao, ArrayExpr ae |
    ao = e and ae = ao.getOperand() and exprFromVariable(ae.getArrayBase(), v)
  )
  or
  exists(PointerDereferenceExpr pe |
    pe = e and exprFromVariable(pe.getOperand(), v)
  )
}

// ---------------------------------------------------------------------------
// Case 2: heap buffer (malloc/calloc/...) zeroed with no subsequent content use
// ---------------------------------------------------------------------------
predicate isAllocationCall(FunctionCall alloc) {
  alloc.getTarget() instanceof AllocationFunction
  or
  alloc.getTarget().hasGlobalOrStdName(["malloc", "calloc", "realloc", "valloc", "pvalloc"])
  or
  alloc.getTarget()
      .getName()
      .regexpMatch("(?i).*(kmalloc|kzalloc|vmalloc|kmem_alloc|vmem_alloc|kmem_zalloc).*")
}

predicate isDeallocationCall(FunctionCall freeCall) {
  freeCall.getTarget() instanceof DeallocationFunction
  or
  freeCall.getTarget().hasGlobalOrStdName(["free", "cfree"])
  or
  freeCall.getTarget()
      .getName()
      .regexpMatch("(?i).*(kfree|vfree|kmem_free|vmem_free|kvfree).*")
}

predicate heapPointer(LocalVariable ptr, FunctionCall alloc) {
  ptr.getUnspecifiedType() instanceof PointerType and
  isAllocationCall(alloc) and
  (
    exists(AssignExpr a |
      a.getLValue() = ptr.getAnAccess() and
      (
        a.getRValue() = alloc
        or
        a.getRValue().(Conversion).getExpr() = alloc
        or
        a.getRValue().getAChild*() = alloc and
        a.getRValue().getUnspecifiedType() instanceof PointerType
      )
    )
    or
    exists(Expr init | init = ptr.getInitializer().getExpr() |
      init = alloc
      or
      init.(Conversion).getExpr() = alloc
      or
      init.getAChild*() = alloc and init.getUnspecifiedType() instanceof PointerType
    )
  )
}

predicate isDeallocOf(FunctionCall fc, LocalVariable ptr) {
  isDeallocationCall(fc) and exprFromVariable(fc.getAnArgument(), ptr)
}

predicate isMemsetOf(FunctionCall fc, LocalVariable ptr) {
  (
    fc.getTarget() instanceof MemsetFunction or
    fc.getTarget() instanceof SecureMemsetFunction
  ) and
  exprFromVariable(fc.getArgument(0), ptr)
}

/**
 * A use of `ptr` after `call` that indicates the buffer contents matter
 * (read, pass to non-free/memset function, field/array access).
 */
predicate heapContentUseAfter(FunctionCall call, LocalVariable ptr) {
  exists(Expr use |
    use = call.getASuccessor*() and
    exprFromVariable(use, ptr) and
    // ignore deallocation of the buffer
    not exists(FunctionCall fc | isDeallocOf(fc, ptr) and fc.getAnArgument().getAChild*() = use.getAChild*()) and
    not isDeallocOf(use.getParent+(), ptr) and
    // ignore further clears of the same buffer
    not exists(FunctionCall fc | isMemsetOf(fc, ptr) and fc.getArgument(0).getAChild*() = use.getAChild*()) and
    not isMemsetOf(use.getParent+(), ptr) and
    (
      // reading contents
      use instanceof FieldAccess
      or
      use instanceof ArrayExpr
      or
      use instanceof PointerDereferenceExpr
      or
      // pointer passed to some other function (e.g. printf, use_pw)
      exists(FunctionCall fc |
        fc.getAnArgument().getAChild*() = use and
        not isDeallocOf(fc, ptr) and
        not isMemsetOf(fc, ptr) and
        fc = call.getASuccessor*()
      )
      or
      // assigned from (load)
      exists(AssignExpr a | a.getRValue().getAChild*() = use and a = call.getASuccessor*())
      or
      // returned
      exists(ReturnStmt r | r.getExpr().getAChild*() = use)
    )
  )
}

/** Destination is the heap buffer itself (or byte offset), not a sub-field. */
predicate wholeHeapBufferDest(Expr dest, LocalVariable ptr) {
  exists(Expr e | e = dest.getUnconverted() |
    e = ptr.getAnAccess()
    or
    // ptr + k / ptr - k / &ptr[k]
    exists(PointerAddExpr add | add = e and add.getLeftOperand().getUnconverted() = ptr.getAnAccess())
    or
    exists(PointerSubExpr sub | sub = e and sub.getLeftOperand().getUnconverted() = ptr.getAnAccess())
    or
    exists(AddressOfExpr ao, ArrayExpr ae |
      ao = e and ae = ao.getOperand() and
      ae.getArrayBase().getUnconverted() = ptr.getAnAccess()
    )
    or
    exists(ArrayExpr ae |
      ae = e and ae.getArrayBase().getUnconverted() = ptr.getAnAccess()
    )
  )
}

predicate heapMemsetMayBeDeleted(FunctionCall call, string why) {
  exists(LocalVariable ptr, FunctionCall alloc |
    heapPointer(ptr, alloc) and
    call.getTarget() instanceof MemsetFunction and
    wholeHeapBufferDest(call.getArgument(0), ptr) and
    not isFromMacroDefinition(call) and
    notDisablingBuiltinMemset(call) and
    not heapContentUseAfter(call, ptr) and
    why = "heap buffer via '" + ptr.getName() + "'"
  )
}

// ---------------------------------------------------------------------------
// Case 3: memset of a field through a pointer local/parameter with no later
// use of that field (OpenZFS gcm_clear_ctx pattern).
// ---------------------------------------------------------------------------
predicate fieldMemsetDest(FunctionCall call, Variable base, Field f) {
  call.getTarget() instanceof MemsetFunction and
  (
    exists(AddressOfExpr ao, FieldAccess fa |
      call.getArgument(0).getUnconverted() = ao and
      fa = ao.getOperand() and
      f = fa.getTarget() and
      exprFromVariable(fa.getQualifier(), base)
    )
    or
    exists(FieldAccess fa |
      call.getArgument(0).getUnconverted() = fa and
      f = fa.getTarget() and
      f.getUnspecifiedType() instanceof ArrayType and
      exprFromVariable(fa.getQualifier(), base)
    )
  )
}

predicate subsequentFieldUse(FunctionCall call, Variable base, Field f) {
  exists(Expr use, FieldAccess fa |
    use = call.getASuccessor*() and
    fa.getAChild*() = use.getAChild*() and
    fa.getTarget() = f and
    exprFromVariable(fa.getQualifier(), base) and
    not exists(FunctionCall fc |
      fieldMemsetDest(fc, base, f) and
      (use = fc or use = fc.getAnArgument+())
    )
  )
}

/** Only zero-fills are security-relevant for DSE of sensitive data. */
predicate memsetFillsWithZero(FunctionCall call) {
  call.getTarget().hasGlobalName(["bzero", "__builtin_bzero"])
  or
  exists(Expr c | c = call.getArgument(1).getFullyConverted() |
    c.getValue() = "0"
  )
  or
  // constant 0 via conversion
  call.getArgument(1).getValue() = "0"
}

/**
 * Holds if a stack local's contents are observed after `call` via whole-object
 * copy, pass-by-value, or address escape — so field memsets cannot be deleted.
 */
predicate stackBaseObservedAfter(FunctionCall call, LocalVariable base) {
  exists(Expr acc | acc = base.getAnAccess() and acc = call.getASuccessor*() |
    // whole-object rvalue use (assignment, pass-by-value)
    exists(AssignExpr a | a.getRValue().getUnconverted() = acc)
    or
    exists(FunctionCall fc | fc.getAnArgument().getUnconverted() = acc)
    or
    exists(ReturnStmt r | r.getExpr().getUnconverted() = acc)
    or
    // address escapes after the memset
    exists(Expr esc |
      variableAddressEscapesTree(acc, esc) and
      esc.getBasicBlock() = call.getASuccessor*().(ControlFlowNode).getBasicBlock()
    )
  )
  or
  // simpler escape check: any later &base or base used where address is taken
  exists(AddressOfExpr ao |
    ao = call.getASuccessor*() and
    ao.getOperand().getUnconverted() = base.getAnAccess()
  )
  or
  exists(AssignExpr a |
    a = call.getASuccessor*() and
    a.getRValue().getUnconverted() = base.getAnAccess()
  )
  or
  exists(FunctionCall fc |
    fc = call.getASuccessor*() and
    fc.getAnArgument().getUnconverted() = base.getAnAccess()
  )
}

/**
 * Well-known socket/address fields that SDK and libc headers zero as part of
 * *constructing* out-parameters (padding / address bytes), not as secret wipes.
 * Whitelist these instead of skipping all non-project headers, so project
 * headers (e.g. OpenZFS inline clears) remain fully in scope.
 *
 * Covers BSD/Linux sockaddr layouts and Windows SOCKADDR_IN / IN6_ADDR
 * (including the `u.Byte` / `u.Word` union members behind s6_bytes macros).
 */
bindingset[lower]
predicate socketAddressTypeName(string lower) {
  lower =
    [
      "sockaddr", "sockaddr_in", "sockaddr_in6", "sockaddr_un", "sockaddr_storage",
      "in_addr", "in6_addr"
    ]
  or
  lower.matches("sockaddr%")
  or
  lower.matches("%in6_addr%")
  or
  lower.matches("%sockaddr_in%")
}

predicate typeHasSocketAddressName(Type t) {
  exists(string n | n = t.getName() and socketAddressTypeName(n.toLowerCase()))
  or
  exists(string n |
    n = t.getUnspecifiedType().getName() and socketAddressTypeName(n.toLowerCase())
  )
  or
  exists(TypedefType td | td = t.getUnspecifiedType() |
    typeHasSocketAddressName(td.getBaseType())
  )
  or
  exists(TypedefType td | td = t | typeHasSocketAddressName(td.getBaseType()))
}

/** Nested union/struct field ultimately belonging to a socket address type. */
predicate fieldInSocketAddressType(Field f) {
  typeHasSocketAddressName(f.getDeclaringType())
  or
  // e.g. IN6_ADDR { union { UCHAR Byte[16]; ... } u; } — Byte declared in union
  exists(Field outer |
    (
      outer.getType().getUnspecifiedType() = f.getDeclaringType()
      or
      outer.getType().getUnspecifiedType().refersTo(f.getDeclaringType())
    ) and
    typeHasSocketAddressName(outer.getDeclaringType())
  )
}

/** Field is padding or address-byte storage on a well-known socket structure. */
predicate isWellKnownNetworkInitOrPaddingField(Field f) {
  exists(string fname | fname = f.getName().toLowerCase() |
    // Distinctive names — effectively unique to socket APIs
    fname =
      [
        "sin_zero", "sin6_zero", "s6_addr", "s6_addr8", "s6_addr16", "s6_addr32",
        "s6_bytes", "s6_words", "s_bytes", "s_words"
      ]
    or
    // Windows IN6_ADDR union members (generic names — require type context)
    fname = ["byte", "word", "u"] and fieldInSocketAddressType(f)
    or
    // Other *zero* padding on sockaddr* / in_* types
    fname.matches("%zero%") and fieldInSocketAddressType(f)
  )
}

predicate isInlineFunction(Function fn) {
  fn.isInline()
  or
  fn.hasSpecifier("always_inline")
  or
  fn.getADeclarationEntry().hasSpecifier("inline")
  or
  fn.getADeclarationEntry().hasSpecifier("always_inline")
}

predicate fieldMemsetMayBeDeleted(FunctionCall call, string why) {
  exists(Variable base, Field f, Function fn |
    fieldMemsetDest(call, base, f) and
    memsetFillsWithZero(call) and
    not isWellKnownNetworkInitOrPaddingField(f) and
    fn = call.getEnclosingFunction() and
    (
      // stack-allocated struct/union local (not a pointer)
      base instanceof LocalVariable and
      not base.getUnspecifiedType() instanceof PointerType and
      not base.getUnspecifiedType() instanceof ReferenceType and
      not stackBaseObservedAfter(call, base)
      or
      // parameter of an inline function (DSE after inlining)
      base instanceof Parameter and isInlineFunction(fn)
    ) and
    not isFromMacroDefinition(call) and
    notDisablingBuiltinMemset(call) and
    not subsequentFieldUse(call, base, f) and
    not exists(AsmStmt asm |
      asm.getEnclosingFunction() = fn and
      asm = call.getASuccessor*()
    ) and
    why = "field '" + f.getName() + "' via '" + base.getName() + "'"
  )
}

// ---------------------------------------------------------------------------
from FunctionCall call, string why
where
  localVarMemsetMayBeDeleted(call, why)
  or
  heapMemsetMayBeDeleted(call, why)
  or
  fieldMemsetMayBeDeleted(call, why)
select call, "Call to memset may be deleted by the compiler (" + why + ")."
