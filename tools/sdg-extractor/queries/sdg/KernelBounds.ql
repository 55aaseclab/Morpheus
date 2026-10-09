import KernelFlow

bindingset[value]
string quoted(string value) {
  result = "\"" + value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"") + "\""
}

string locationKey(Locatable element) {
  result = element.getFile().getRelativePath() + ":" +
    element.getLocation().getStartLine().toString() + ":" +
    element.getLocation().getStartColumn().toString()
}

string optionalConstant(Expr expression) {
  if exists(expression.getFullyConverted().getValue())
  then result = expression.getFullyConverted().getValue()
  else result = ""
}

string expressionKey(Expr expression) {
  result = locationKey(expression) + ":" + expression.getAPrimaryQlClass()
}

predicate constantValue(Expr expression, string value) {
  value = expression.getFullyConverted().getValue()
}

predicate comparisonText(ComparisonOperation comparison, string operator,
                         Expr value, string constant) {
  comparison instanceof EQExpr and operator = "Eq" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
  or
  comparison instanceof NEExpr and operator = "Ne" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
  or
  comparison instanceof LTExpr and operator = "Lt" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
  or
  comparison instanceof LEExpr and operator = "Le" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
  or
  comparison instanceof GTExpr and operator = "Gt" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
  or
  comparison instanceof GEExpr and operator = "Ge" and
    (value = comparison.getLeftOperand() or value = comparison.getRightOperand()) and
    exists(Expr other |
      (other = comparison.getLeftOperand() or other = comparison.getRightOperand()) and
      other != value and constantValue(other, constant))
}

from string section, string key, string value
where
  exists(ComparisonOperation comparison, string operator |
    (comparison instanceof EQExpr and operator = "Eq"
     or comparison instanceof NEExpr and operator = "Ne"
     or comparison instanceof LTExpr and operator = "Lt"
     or comparison instanceof LEExpr and operator = "Le"
     or comparison instanceof GTExpr and operator = "Gt"
     or comparison instanceof GEExpr and operator = "Ge") and
    section = "comparison" and key = locationKey(comparison) and
    value = "{\"left\":" + quoted(expressionKey(comparison.getLeftOperand())) +
      ",\"right\":" + quoted(expressionKey(comparison.getRightOperand())) +
      ",\"left_constant\":" + quoted(optionalConstant(comparison.getLeftOperand())) +
      ",\"right_constant\":" + quoted(optionalConstant(comparison.getRightOperand())) +
      ",\"operator\":" + quoted(operator) +
      ",\"function\":" + quoted(comparison.getEnclosingFunction().getName()) +
      ",\"location\":{\"file\":" + quoted(comparison.getFile().getRelativePath()) +
      ",\"line\":" + comparison.getLocation().getStartLine().toString() + "}}"
  )
  or
  exists(ComparisonOperation comparison, Expr compared, string operator, string constant |
    comparisonText(comparison, operator, compared, constant) and
    section = "bound" and
    key = expressionKey(compared) + ":" + operator + ":" + constant and
    value = "{\"value\":" + quoted(expressionKey(compared)) +
      ",\"operator\":" + quoted(operator) +
      ",\"constant\":" + quoted(constant) +
      ",\"function\":" + quoted(comparison.getEnclosingFunction().getName()) +
      ",\"location\":{\"file\":" + quoted(comparison.getFile().getRelativePath()) +
      ",\"line\":" + comparison.getLocation().getStartLine().toString() + "}}"
  )
select section, key, value
