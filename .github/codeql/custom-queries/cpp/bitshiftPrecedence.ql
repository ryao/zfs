/**
 * @name Bit shift precedence issue
 * @description Detects bit shift operations where an arithmetic operation could be misinterpreted due to lack of parentheses, specifically when the left child is an arithmetic expression other than multiplication, or the right child is an arithmetic expression.
 * @kind problem
 * @severity warning
 * @id cpp/bitshift-precedence-issue
 */

import cpp

class NonParenthesizedArithmeticExpr extends Expr {
  NonParenthesizedArithmeticExpr() {
    (
      this instanceof AddExpr or
      this instanceof SubExpr or
      this instanceof MulExpr or
      this instanceof DivExpr or
      this instanceof RemExpr
    ) and
    not exists(ParenthesisExpr pe | pe.getExpr() = this)
  }
}

from Expr bitShiftExpr, NonParenthesizedArithmeticExpr arithExpr
where
  (
    bitShiftExpr instanceof LShiftExpr or
    bitShiftExpr instanceof RShiftExpr
  ) and
  (
    (
      // Check if the left operand is a non-parenthesized arithmetic expression excluding multiplication
      arithExpr = bitShiftExpr.(LShiftExpr).getLeftOperand() and
      not arithExpr instanceof MulExpr
    ) or
    (
      // Check if the right operand is a non-parenthesized arithmetic expression
      arithExpr = bitShiftExpr.(LShiftExpr).getRightOperand()
    ) or
    (
      // Check if the left operand is a non-parenthesized arithmetic expression excluding multiplication
      arithExpr= bitShiftExpr.(RShiftExpr).getLeftOperand() and
      not arithExpr instanceof MulExpr
    ) or
    (
      // Check if the right operand is a non-parenthesized arithmetic expression
      arithExpr = bitShiftExpr.(RShiftExpr).getRightOperand()
    )
  )
select bitShiftExpr,
       "This bit shift operation's operand is an arithmetic operation without parentheses and may not be evaluated as intended due to operator precedence." 
