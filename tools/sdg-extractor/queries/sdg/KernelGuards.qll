import KernelFacts
import semmle.code.cpp.controlflow.Guards

predicate guardedMemory(Expr condition, Expr sink, Expr operand, string operation, boolean branch) {
  sinkOperand(sink, operand, operation) and
  (
    condition.(GuardCondition).controls(sink.getBasicBlock(), branch)
    or
    exists(IfStmt conditional |
      condition = conditional.getCondition() and
      (sink.getEnclosingStmt().getParentStmt*() = conditional.getThen() and branch = true
       or sink.getEnclosingStmt().getParentStmt*() = conditional.getElse() and branch = false)
    )
  )
}

predicate guardValue(Expr condition, Expr value) {
  condition = value
  or
  exists(Expr child | expressionChild(condition, child, _) and guardValue(child, value))
}

predicate memoryGuardValue(Expr value) {
  exists(Expr condition | guardedMemory(condition, _, _, _, _) and guardValue(condition, value))
}
