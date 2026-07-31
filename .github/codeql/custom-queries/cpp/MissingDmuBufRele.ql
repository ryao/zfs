/**
 * @name Missing dmu_buf_rele after successful hold
 * @description Finds paths where a DMU buffer is successfully held via
 *   dmu_bonus_hold / dmu_buf_hold* (or a wrapper that ultimately calls one)
 *   but is not released with dmu_buf_rele (or a rele wrapper) before the
 *   enclosing function returns. Catches the brt_vdev_load() class of bug:
 *   hold, then return (error) on a later failure without dmu_buf_rele.
 *
 *   Interprocedural handling:
 *   - Hold wrappers: functions that acquire a hold and pass it out via a
 *     dmu_buf_t ** parameter without releasing on the success path.
 *   - Rele wrappers: functions that release a dmu_buf_t * parameter.
 *   Wrappers are discovered transitively (wrappers of wrappers).
 *
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id zfs/missing-dmu-buf-rele
 * @tags correctness
 *       resource-leak
 *       external/cwe/cwe-772
 */

import cpp

/*
 * ---------------------------------------------------------------------------
 * Primitive hold / rele API (OpenZFS)
 * ---------------------------------------------------------------------------
 *
 * Hold functions write a held dmu_buf_t * through an out-parameter and return
 * 0 on success. The out-parameter index is the dmu_buf_t ** argument.
 *
 * Rele functions take the dmu_buf_t * as their first argument.
 */

/** Out-parameter index of a primitive hold for `dmu_buf_t **`. */
predicate primitiveHoldOutParam(Function f, int outIdx) {
  exists(string n | n = f.getName() |
    // int dmu_bonus_hold(os, object, tag, dmu_buf_t **dbp)
    (n = "dmu_bonus_hold" and outIdx = 3)
    or
    // int dmu_bonus_hold_by_dnode(dn, tag, dmu_buf_t **dbp, flags)
    (n = "dmu_bonus_hold_by_dnode" and outIdx = 2)
    or
    // int dmu_buf_hold(os, object, offset, tag, dmu_buf_t **dbp, flags)
    (n = "dmu_buf_hold" and outIdx = 4)
    or
    // int dmu_buf_hold_by_dnode(dn, offset, tag, dmu_buf_t **dbp, flags)
    (n = "dmu_buf_hold_by_dnode" and outIdx = 3)
    or
    // int dmu_buf_hold_noread(os, object, offset, tag, dmu_buf_t **dbp)
    (n = "dmu_buf_hold_noread" and outIdx = 4)
    or
    // int dmu_buf_hold_noread_by_dnode(dn, offset, tag, dmu_buf_t **dbp)
    (n = "dmu_buf_hold_noread_by_dnode" and outIdx = 3)
  )
}

predicate isPrimitiveRele(Function f) { f.getName() = "dmu_buf_rele" }

/** Array-form holds (paired with dmu_buf_rele_array, not dmu_buf_rele). */
predicate primitiveArrayHoldOutParam(Function f, int outIdx) {
  exists(string n | n = f.getName() |
    // int dmu_buf_hold_array(..., int *numbufs, dmu_buf_t ***dbp, ...)
    (n = "dmu_buf_hold_array" and outIdx = 7)
    or
    (n = "dmu_buf_hold_array_by_dnode" and outIdx = 6)
    or
    (n = "dmu_buf_hold_array_by_bonus" and outIdx = 6)
  )
}

predicate isPrimitiveArrayRele(Function f) { f.getName() = "dmu_buf_rele_array" }

/*
 * ---------------------------------------------------------------------------
 * Type helpers
 * ---------------------------------------------------------------------------
 */

/**
 * True if `t` is the DMU buffer object type.
 *
 * OpenZFS uses `typedef struct dmu_buf { ... } dmu_buf_t`. After
 * getUnspecifiedType() the typedef is erased and only the struct name
 * `dmu_buf` remains, so match both names.
 */
predicate isDmuBufType(Type t) {
  exists(string n | n = t.getUnspecifiedType().getName() |
    n = "dmu_buf_t" or n = "dmu_buf"
  )
}

/** True if `t` is (typedef to) `dmu_buf_t *` / `struct dmu_buf *`. */
predicate isDmuBufPtr(Type t) {
  isDmuBufType(t.getUnspecifiedType().(PointerType).getBaseType())
}

/** True if `t` is (typedef to) `dmu_buf_t **`. */
predicate isDmuBufPtrPtr(Type t) {
  isDmuBufPtr(t.getUnspecifiedType().(PointerType).getBaseType())
}

/** True if `t` is (typedef to) `dmu_buf_t ***` (array-hold out-param). */
predicate isDmuBufPtrPtrPtr(Type t) {
  isDmuBufPtrPtr(t.getUnspecifiedType().(PointerType).getBaseType())
}

/**
 * Variable named by an out-parameter expression.
 * Handles both `&v` (v is dmu_buf_t *) and plain `dbp` (dmu_buf_t **).
 */
Variable outParamTarget(Expr e) {
  result = e.(AddressOfExpr).getOperand().(VariableAccess).getTarget()
  or
  result = e.(VariableAccess).getTarget() and isDmuBufPtrPtr(result.getType())
}

/*
 * ---------------------------------------------------------------------------
 * Interprocedural hold / rele wrappers
 * ---------------------------------------------------------------------------
 */

/** `arg` is the hold out-argument referring to wrapper parameter `p`. */
predicate holdArgIsOutParam(Expr arg, Parameter p) {
  // passthrough: hold(..., dbp) where dbp is dmu_buf_t ** parameter
  arg.(VariableAccess).getTarget() = p
  or
  // hold(..., &local) is not the out-param; handled separately
  arg.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = p
}

/**
 * `f` is a hold-like function whose out-parameter at `outIdx` receives the
 * held `dmu_buf_t *` on success (return 0).
 *
 * Discovered transitively so thin wrappers are treated like the primitive.
 */
predicate holdFunction(Function f, int outIdx) {
  primitiveHoldOutParam(f, outIdx)
  or
  // Passthrough wrapper:
  //   int wrap(..., dmu_buf_t **dbp) { return dmu_bonus_hold(..., dbp); }
  exists(Parameter p, FunctionCall fc, int calleesOut |
    p = f.getParameter(outIdx) and
    isDmuBufPtrPtr(p.getType()) and
    fc.getEnclosingFunction() = f and
    holdFunction(fc.getTarget(), calleesOut) and
    holdArgIsOutParam(fc.getArgument(calleesOut), p)
  )
  or
  // Local-then-assign wrapper:
  //   int wrap(..., dmu_buf_t **dbp) {
  //     dmu_buf_t *db;
  //     int err = dmu_bonus_hold(..., &db);
  //     if (err) return err;
  //     *dbp = db;
  //     return 0;
  //   }
  exists(Parameter p, FunctionCall fc, int calleesOut, Variable local, AssignExpr a |
    p = f.getParameter(outIdx) and
    isDmuBufPtrPtr(p.getType()) and
    fc.getEnclosingFunction() = f and
    holdFunction(fc.getTarget(), calleesOut) and
    outParamTarget(fc.getArgument(calleesOut)) = local and
    isDmuBufPtr(local.getType()) and
    a.getEnclosingFunction() = f and
    a.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = p and
    a.getRValue().(VariableAccess).getTarget() = local and
    fc.getASuccessor*() = a and
    // Must not rele `local` before exporting it
    not exists(FunctionCall rele |
      releCallOn(rele, local) and
      fc.getASuccessor*() = rele and
      rele.getASuccessor*() = a
    )
  )
}

/**
 * `f` releases its parameter at `bufIdx` (a `dmu_buf_t *`) by calling a
 * rele-like function on that parameter.
 */
predicate releFunction(Function f, int bufIdx) {
  isPrimitiveRele(f) and bufIdx = 0
  or
  exists(Parameter p, FunctionCall fc, int calleesBuf |
    p = f.getParameter(bufIdx) and
    isDmuBufPtr(p.getType()) and
    fc.getEnclosingFunction() = f and
    releFunction(fc.getTarget(), calleesBuf) and
    fc.getArgument(calleesBuf).(VariableAccess).getTarget() = p
  )
}

/** Array-hold functions (separate resource class). */
predicate arrayHoldFunction(Function f, int outIdx) {
  primitiveArrayHoldOutParam(f, outIdx)
  or
  exists(Parameter p, FunctionCall fc, int calleesOut |
    p = f.getParameter(outIdx) and
    isDmuBufPtrPtrPtr(p.getType()) and
    fc.getEnclosingFunction() = f and
    arrayHoldFunction(fc.getTarget(), calleesOut) and
    (
      fc.getArgument(calleesOut).(VariableAccess).getTarget() = p
      or
      outParamTarget(fc.getArgument(calleesOut)) = p
    )
  )
}

predicate arrayReleFunction(Function f, int bufIdx) {
  isPrimitiveArrayRele(f) and bufIdx = 0
  or
  exists(Parameter p, FunctionCall fc, int calleesBuf |
    p = f.getParameter(bufIdx) and
    fc.getEnclosingFunction() = f and
    arrayReleFunction(fc.getTarget(), calleesBuf) and
    fc.getArgument(calleesBuf).(VariableAccess).getTarget() = p
  )
}

/*
 * ---------------------------------------------------------------------------
 * Hold / rele calls against a specific variable
 * ---------------------------------------------------------------------------
 */

/** Primitive-or-wrapper rele of variable `v` (defined early for use in holdFunction). */
predicate releCallOn(FunctionCall call, Variable v) {
  exists(int bufIdx |
    releFunction(call.getTarget(), bufIdx) and
    call.getArgument(bufIdx).(VariableAccess).getTarget() = v
  )
}

/** `call` holds into variable `v` (`dmu_buf_t * v` via `&v`). */
predicate isHoldCall(FunctionCall call, Variable v) {
  exists(int outIdx |
    holdFunction(call.getTarget(), outIdx) and
    // Prefer &v form (normal OpenZFS style)
    call.getArgument(outIdx).(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v and
    isDmuBufPtr(v.getType())
  )
}

/** `call` releases variable `v`. */
predicate isReleCall(FunctionCall call, Variable v) { releCallOn(call, v) }

/** Array hold into `v` where `v` is `dmu_buf_t **`. */
predicate isArrayHoldCall(FunctionCall call, Variable v) {
  exists(int outIdx |
    arrayHoldFunction(call.getTarget(), outIdx) and
    outParamTarget(call.getArgument(outIdx)) = v
  )
}

predicate isArrayReleCall(FunctionCall call, Variable v) {
  exists(int bufIdx |
    arrayReleFunction(call.getTarget(), bufIdx) and
    call.getArgument(bufIdx).(VariableAccess).getTarget() = v
  )
}

/*
 * ---------------------------------------------------------------------------
 * Successful-hold vs. hold-failure early returns
 * ---------------------------------------------------------------------------
 *
 * OpenZFS style:
 *   error = dmu_bonus_hold(..., &db);
 *   if (error != 0)
 *       return (error);
 *
 * or:
 *   if ((error = dmu_bonus_hold(..., &db)) != 0)
 *       return (error);
 *
 * Those failure returns must not be reported as leaks.
 */

/** Assignment of `holdCall`'s result into variable `err`. */
predicate holdResultAssigned(FunctionCall holdCall, Variable err) {
  exists(AssignExpr a |
    a.getRValue() = holdCall and
    a.getLValue().(VariableAccess).getTarget() = err
  )
  or
  // int err = dmu_bonus_hold(...);
  exists(Initializer init |
    init.getExpr() = holdCall and
    init.getDeclaration() = err
  )
}

/** Condition expression tests `err` for non-zero / failure. */
predicate conditionMentionsError(Expr cond, Variable err) {
  cond.(VariableAccess).getTarget() = err
  or
  exists(NEExpr ne |
    ne = cond and
    (
      ne.getLeftOperand().(VariableAccess).getTarget() = err or
      ne.getRightOperand().(VariableAccess).getTarget() = err
    )
  )
  or
  exists(EQExpr eq |
    eq = cond and
    (
      eq.getLeftOperand().(VariableAccess).getTarget() = err or
      eq.getRightOperand().(VariableAccess).getTarget() = err
    )
  )
  or
  exists(NotExpr not_ |
    not_ = cond and conditionMentionsError(not_.getOperand(), err)
  )
  or
  conditionMentionsError(cond.(Conversion).getExpr(), err)
}

/**
 * `ret` is the early return that propagates `holdCall`'s own failure
 * (non-zero). These paths never own a held buffer.
 *
 * Important: only the *first* error-check after the hold counts. A later
 * `error = dmu_read(...); if (error != 0) return (error);` must NOT match,
 * or real leaks are suppressed. Require that `err` is not reassigned
 * between the hold and this if.
 */
predicate isHoldFailureReturn(FunctionCall holdCall, ReturnStmt ret) {
  exists(Variable err, IfStmt ifs |
    holdResultAssigned(holdCall, err) and
    exists(Expr cond | cond = ifs.getCondition().getFullyConverted() |
      conditionMentionsError(cond, err)
    ) and
    holdCall.getASuccessor*() = ifs and
    // No reassignment of err between hold and this check
    not exists(AssignExpr a |
      a.getLValue().(VariableAccess).getTarget() = err and
      not a.getRValue() = holdCall and
      holdCall.getASuccessor*() = a and
      a.getASuccessor*() = ifs
    ) and
    ifs.getThen().getAChild*() = ret and
    (
      ret.getExpr().(VariableAccess).getTarget() = err
      or
      ret.getExpr().getAChild*().(VariableAccess).getTarget() = err
    )
  )
}

/** `if ((err = hold(...)) != 0) return err;` */
predicate isHoldFailureReturnAssignInCond(FunctionCall holdCall, ReturnStmt ret) {
  exists(IfStmt ifs, AssignExpr a, Variable err |
    a.getRValue() = holdCall and
    a.getLValue().(VariableAccess).getTarget() = err and
    ifs.getCondition().getAChild*() = a and
    ifs.getThen().getAChild*() = ret and
    ret.getExpr().getAChild*().(VariableAccess).getTarget() = err
  )
}

predicate holdFailureReturn(FunctionCall holdCall, ReturnStmt ret) {
  isHoldFailureReturn(holdCall, ret)
  or
  isHoldFailureReturnAssignInCond(holdCall, ret)
}

/*
 * ---------------------------------------------------------------------------
 * Escapes: buffer ownership transferred out of the function
 * ---------------------------------------------------------------------------
 */

/**
 * On some path from `holdCall` to `ret`, the held buffer in `v` is given to
 * the caller or stored for later release — not a local leak.
 */
predicate bufferEscapes(FunctionCall holdCall, Variable v, ReturnStmt ret) {
  // Returned directly: return db;
  ret.getExpr().(VariableAccess).getTarget() = v and
  holdCall.getASuccessor*() = ret
  or
  // Written through an out-parameter: *dbp = v; return ...
  exists(Parameter p, AssignExpr a |
    p = holdCall.getEnclosingFunction().getAParameter() and
    isDmuBufPtrPtr(p.getType()) and
    a.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = p and
    a.getRValue().(VariableAccess).getTarget() = v and
    holdCall.getASuccessor*() = a and
    a.getASuccessor*() = ret
  )
  or
  // Assigned into a struct field / global (long-lived ownership).
  // Conservative: treat as escape to avoid noisy FPs on cache/objset code.
  exists(AssignExpr a |
    a.getRValue().(VariableAccess).getTarget() = v and
    (
      a.getLValue() instanceof FieldAccess
      or
      a.getLValue().(VariableAccess).getTarget() instanceof GlobalVariable
    ) and
    holdCall.getASuccessor*() = a and
    a.getASuccessor*() = ret
  )
}

/*
 * ---------------------------------------------------------------------------
 * Leak: successful hold reaches a return with no rele in between
 * ---------------------------------------------------------------------------
 */

predicate reachesWithoutRele(FunctionCall holdCall, Variable v, ControlFlowNode n) {
  isHoldCall(holdCall, v) and
  holdCall.getASuccessor*() = n and
  not exists(FunctionCall rele |
    isReleCall(rele, v) and
    holdCall.getASuccessor*() = rele and
    rele.getASuccessor*() = n
  )
}

/**
 * A return that still owns `v` after `holdCall` succeeded — the defect.
 */
predicate missingReleOnReturn(FunctionCall holdCall, Variable v, ReturnStmt ret, Function f) {
  f = holdCall.getEnclosingFunction() and
  isHoldCall(holdCall, v) and
  ret.getEnclosingFunction() = f and
  reachesWithoutRele(holdCall, v, ret) and
  // Not the hold's own failure path
  not holdFailureReturn(holdCall, ret) and
  // Ownership did not leave the function
  not bufferEscapes(holdCall, v, ret) and
  // Ignore success returns of hold wrappers that export `v` via out-param
  not exists(int outIdx, Parameter p, AssignExpr a |
    holdFunction(f, outIdx) and
    p = f.getParameter(outIdx) and
    a.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = p and
    a.getRValue().(VariableAccess).getTarget() = v
  )
}

/*
 * Same shape for array holds / dmu_buf_rele_array.
 */

predicate reachesWithoutArrayRele(FunctionCall holdCall, Variable v, ControlFlowNode n) {
  isArrayHoldCall(holdCall, v) and
  holdCall.getASuccessor*() = n and
  not exists(FunctionCall rele |
    isArrayReleCall(rele, v) and
    holdCall.getASuccessor*() = rele and
    rele.getASuccessor*() = n
  )
}

predicate missingArrayReleOnReturn(FunctionCall holdCall, Variable v, ReturnStmt ret, Function f) {
  f = holdCall.getEnclosingFunction() and
  isArrayHoldCall(holdCall, v) and
  ret.getEnclosingFunction() = f and
  reachesWithoutArrayRele(holdCall, v, ret) and
  not holdFailureReturn(holdCall, ret)
}

/*
 * ---------------------------------------------------------------------------
 * Results
 * ---------------------------------------------------------------------------
 */

from FunctionCall holdCall, Variable v, ReturnStmt ret, Function f, string kind
where
  (
    missingReleOnReturn(holdCall, v, ret, f) and
    kind = "dmu_buf_rele"
  )
  or
  (
    missingArrayReleOnReturn(holdCall, v, ret, f) and
    kind = "dmu_buf_rele_array"
  )
select ret,
  "Possible missing " + kind + " of $@ on this return path after successful hold $@ in "
    + f.getName() + "().",
  v, v.getName(),
  holdCall, holdCall.getTarget().getName()
