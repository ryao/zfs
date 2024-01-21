/**
 * @name Deprecated function usage detection
 * @description Detects functions whose usage is banned from the OpenZFS
 *              codebase due to QA concerns.
 * @kind problem
 * @severity error
 * @id cpp/deprecated-function-usage
*/

import cpp

predicate isDeprecatedFunction(Function f) {
  f.getName() = "strtok" or
  f.getName() = "__xpg_basename" or
  f.getName() = "basename" or
  f.getName() = "dirname" or
  f.getName() = "bcopy" or
  f.getName() = "bcmp" or
  f.getName() = "bzero" or
  f.getName() = "asctime" or
  f.getName() = "asctime_r"
}

string getReplacementMessage(Function f) {
  if f.getName() = "strtok" then
    result = "strtok_r(3)"
  else if f.getName() = "__xpg_basename" then
    result = "zfs_basename()"
  else if f.getName() = "basename" then
    result = "zfs_basename()"
  else if f.getName() = "dirname" then
    result = "zfs_dirnamelen()"
  else if f.getName() = "bcopy" then
    result = "memcpy(3)/memmove(3)"
  else if f.getName() = "bcmp" then
    result = "memcmp(3)"
  else if f.getName() = "bzero" then
    result = "memset(3)"
  else if f.getName() = "asctime" then
    result = "strftime(3)"
  else
    result = "strftime(3)"
}

from FunctionCall fc, Function f
where
  fc.getTarget() = f and
  isDeprecatedFunction(f)
select fc, "Usage of '" + f.getName() + "' is deprecated, consider using '" +
  getReplacementMessage(f) + "' instead."
