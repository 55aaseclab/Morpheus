import KernelExpressions

from Expr expression
where
  (exists(expression.getEnclosingStmt().getEnclosingFunction().getBlock()) or
   exists(expression.getUnconverted().getEnclosingFunction().getBlock())) and
  not exists(expressionJson(expression))
select concat(string location | location = locationKey(expression) | location, ",") as location,
  expressionKey(expression) as identity,
  expression.toString() as description,
  concat(string primary | primary = expression.getAPrimaryQlClass() | primary, ",") as classes,
  concat(Type type | type = expression.getType() | type.toString(), ",") as types,
  concat(string encoded | encoded = typeJson(expression.getType()) | encoded, ",") as encoded_type,
  concat(string encoded | encoded = declarationKey(expression.(VariableAccess).getTarget()) | encoded, ",") as declaration,
  concat(string encoded | encoded = functionKey(expression.getEnclosingFunction()) | encoded, ",") as function_key,
  concat(string encoded | encoded = locationJson(expression) | encoded, ",") as encoded_location
