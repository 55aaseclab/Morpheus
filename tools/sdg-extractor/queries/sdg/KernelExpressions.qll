import cpp

bindingset[character]
private string jsonCharacter(string character) {
  if character = "\"" then result = "\\\""
  else if character = "\\" then result = "\\\\"
  else if character.codePointAt(0) < 32
  then exists(int code |
    code = character.codePointAt(0) |
    result = "\\u00" + "0123456789abcdef".charAt(code / 16) +
      "0123456789abcdef".charAt(code % 16)
  )
  else result = character
}

bindingset[value]
string quoted(string value) {
  if value.regexpMatch("(?s).*[\\x00-\\x1f].*")
  then result = "\"" + concat(int position |
      position in [0 .. value.length() - 1] |
      jsonCharacter(value.charAt(position)), "" order by position
    ) + "\""
  else result = "\"" + value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"") + "\""
}

private Location sourceLocation(Locatable element) {
  if exists(element.getLocation().getFile().getRelativePath())
  then result = element.getLocation()
  else result = sourceLocation(element.(Conversion).getExpr())
}

string locationKey(Locatable element) {
  result = min(Location location | location = sourceLocation(element) |
    location.getFile().getRelativePath() + ":" +
    location.getStartLine().toString() + ":" +
    location.getStartColumn().toString() + ":" +
    location.getEndLine().toString() + ":" +
    location.getEndColumn().toString()
  )
}

string locationJson(Locatable element) {
  result = min(Location location | location = sourceLocation(element) |
    "{\"file\":" + quoted(location.getFile().getRelativePath()) +
    ",\"line\":" + location.getStartLine().toString() +
    ",\"column\":" + location.getStartColumn().toString() + "}"
  )
}

string functionKey(Function function) {
  result = locationKey(function) + ":" + function.getName()
}

string declarationKey(Declaration declaration) {
  if exists(DeclStmt statement | statement.getADeclaration() = declaration)
  then exists(DeclStmt statement, int position |
    statement.getDeclaration(position) = declaration |
    result = syntaxKey(statement) + "/declaration:" + position.toString() + ":" +
      declarationName(declaration)
  )
  else result = declarationOwner(declaration) + locationKey(declaration) + ":" +
      declarationName(declaration)
}

private string declarationName(Declaration declaration) {
  if exists(declaration.getQualifiedName()) then result = declaration.getQualifiedName()
  else if exists(declaration.getName()) then result = declaration.getName()
  else if declaration instanceof Field
  then result = "anonymous-field:" + declaration.(Field).getByteOffset().toString() + ":" +
    declaration.(Field).getInitializationOrder().toString()
  else result = "anonymous-declaration"
}

private string primaryClass(Element element) {
  if exists(element.getAPrimaryQlClass()) then result = min(element.getAPrimaryQlClass())
  else result = "Expr"
}

private string declarationOwner(Declaration declaration) {
  if declaration instanceof LocalScopeVariable
  then result = functionKey(declaration.(LocalScopeVariable).getFunction()) + "/"
  else result = ""
}

private string syntaxOwner(Element element) {
  if exists(element.(Stmt).getEnclosingFunction())
  then result = functionKey(element.(Stmt).getEnclosingFunction()) + "/"
  else if exists(element.(Expr).getEnclosingFunction())
  then result = functionKey(element.(Expr).getEnclosingFunction()) + "/"
  else result = ""
}

cached
string syntaxKey(Element element) {
  if element instanceof Conversion
  then result = syntaxKey(element.(Conversion).getExpr()) + "/conversion:" +
    primaryClass(element) + ":" + element.(Expr).getType().toString()
  else if exists(Expr parent | parent.getAChild() = element)
  then exists(Expr parent, int position |
    parent.getChild(position) = element |
    result = syntaxKey(parent) + "/e" + position.toString()
  )
  else if exists(Stmt parent | parent.getAChild() = element)
  then exists(Stmt parent, int position |
    parent.getChild(position) = element |
    result = syntaxKey(parent) + "/s" + position.toString()
  )
  else if element.(Stmt).getParent() instanceof StmtExpr
  then result = syntaxKey(element.(Stmt).getParent()) + "/body"
  else if exists(Variable variable | variable.getInitializer().getExpr() = element)
  then exists(Variable variable |
    variable.getInitializer().getExpr() = element |
    result = declarationKey(variable) + "/initializer"
  )
  else result = syntaxOwner(element) + locationKey(element.(Locatable)) + ":" +
    primaryClass(element)
}

string expressionKey(Expr expression) { result = syntaxKey(expression) }

string parameterKey(Parameter parameter) { result = "parameter:" + declarationKey(parameter) }

private Type adjustedParameterType(Parameter parameter) {
  if parameter.getType().getUnspecifiedType() instanceof ArrayType
  then result.(PointerType).getBaseType() = parameter.getType().getUnspecifiedType().(ArrayType).getBaseType()
  else result = parameter.getType()
}

string parameterJson(Parameter parameter) {
  result = "{\"id\":" + quoted(parameterKey(parameter)) +
    ",\"function\":" + quoted(functionKey(parameter.getFunction())) +
    ",\"location\":" + locationJson(parameter) +
    ",\"class\":\"ParameterValue\",\"text\":" + quoted(parameter.getName()) +
    ",\"declaration\":" + quoted(declarationKey(parameter)) +
    ",\"type\":" + typeJson(adjustedParameterType(parameter)) + ",\"children\":[]}"
}

string signedness(Type type) {
  if type.getUnspecifiedType().(IntegralType).isUnsigned() then result = "Unsigned"
  else if type.getUnspecifiedType().(IntegralType).isSigned() then result = "Signed"
  else result = "Unknown"
}

string typeJson(Type type) {
  result = "{\"name\":" + quoted(type.toString()) +
    ",\"signedness\":" + quoted(signedness(type)) + typeSizeJson(type) +
    ",\"kind\":" + quoted(typeKind(type)) +
    ",\"byte_order\":" + quoted(targetByteOrder()) +
    ",\"storage_byte_order\":" + quoted(storageByteOrder(type)) + pointerSizeJson(type) + "}"
}

private predicate byteOrderMacro(string byteOrder) {
  exists(Macro macro |
    macro.getName() in ["__BYTE_ORDER", "__BYTE_ORDER__"] and
    (macro.getBody().regexpMatch(".*LITTLE_ENDIAN.*") and byteOrder = "Little"
     or macro.getBody().regexpMatch(".*BIG_ENDIAN.*") and byteOrder = "Big")
  )
}

string targetByteOrder() {
  if byteOrderMacro("Little") and not byteOrderMacro("Big") then result = "Little"
  else if byteOrderMacro("Big") and not byteOrderMacro("Little") then result = "Big"
  else result = "Unknown"
}

private string storageByteOrder(Type type) {
  if type.toString().regexpMatch("(const |volatile )*__le(16|32|64)") then result = "Little"
  else if type.toString().regexpMatch("(const |volatile )*__be(16|32|64)") then result = "Big"
  else result = targetByteOrder()
}

private string typeKind(Type type) {
  if type.getUnspecifiedType() instanceof IntegralType then result = "integer"
  else if type.getUnspecifiedType() instanceof PointerType then result = "pointer"
  else if type.getUnspecifiedType() instanceof ArrayType then result = "array"
  else result = "other"
}

private string pointerSizeJson(Type type) {
  if exists(type.getUnspecifiedType().(PointerType).getBaseType().getSize())
  then result = ",\"stride\":" + type.getUnspecifiedType().(PointerType).getBaseType().getSize().toString()
  else result = ""
}

private string typeSizeJson(Type type) {
  if exists(type.getSize()) then result = ",\"width\":" + (8 * type.getSize()).toString()
  else result = ""
}

predicate expressionChild(Expr parent, Expr child, int position) {
  not parent instanceof ConditionalExpr and child = parent.getChild(position).getFullyConverted()
  or
  exists(ConditionalExpr conditional |
    parent = conditional and
    (position = 0 and child = conditional.getCondition().getFullyConverted()
     or position = 1 and child = conditional.getThen().getFullyConverted()
     or position = 2 and child = conditional.getElse().getFullyConverted())
  )
  or
  parent instanceof Conversion and child = parent.(Conversion).getExpr() and position = 0
  or
  parent instanceof StmtExpr and child = parent.(StmtExpr).getResultExpr().getFullyConverted() and position = 0
}

private string expressionConstant(Expr expression) {
  if exists(expression.getValue())
  then result = ",\"constant\":" + quoted(expression.getValue())
  else result = ""
}

private string expressionOperator(Expr expression) {
  if expression instanceof Operation
  then result = ",\"operator\":" + quoted(expression.(Operation).getOperator())
  else result = ""
}

private string expressionDeclaration(Expr expression) {
  if exists(declarationKey(expression.(VariableAccess).getTarget()))
  then result = ",\"declaration\":" + quoted(declarationKey(expression.(VariableAccess).getTarget()))
  else if expression instanceof VariableAccess then result = ",\"declaration_unresolved\":true"
  else result = ""
}

private string expressionCallee(Expr expression) {
  if exists(expression.(Call).getTarget())
  then result = ",\"callee\":" + quoted(expression.(Call).getTarget().getName())
  else result = ""
}

private string expressionStorage(Expr expression) {
  if expression instanceof FieldAccess
  then result = fieldLayoutJson(expression.(FieldAccess).getTarget())
  else if expression instanceof VariableAccess
  then exists(Variable variable |
    variable = expression.(VariableAccess).getTarget() |
    if variable instanceof LocalScopeVariable and not variable.isStatic()
    then result = ",\"storage\":\"automatic\""
    else result = ",\"storage\":\"static\""
  )
  else result = ""
}

private string fieldLayoutJson(Field field) {
  if field instanceof BitField then result = ",\"bitfield\":true"
  else if exists(field.getByteOffset())
  then result = ",\"field_offset\":" + field.getByteOffset().toString()
  else result = ",\"field_offset_unresolved\":true"
}

private string allocationSizeJson(Expr expression) {
  if expression.(Call).getTarget().getAnAttribute().hasName("alloc_size")
  then result = ",\"allocation_size\":[" + concat(int ordinal, int position |
    exists(Attribute attribute |
      attribute = expression.(Call).getTarget().getAnAttribute() and attribute.hasName("alloc_size") and
      position = attribute.getArgument(ordinal).getValueInt() - 1
    ) |
    quoted(expressionKey(expression.(Call).getArgument(position).getFullyConverted())),
    "," order by ordinal, position) + "]"
  else result = ""
}

string expressionJson(Expr expression) {
  result = "{\"id\":" + quoted(expressionKey(expression)) +
    ",\"function\":" + quoted(functionKey(expression.getEnclosingFunction())) +
    ",\"location\":" + locationJson(expression) +
    ",\"class\":" + quoted(primaryClass(expression)) +
    ",\"text\":" + quoted(expression.toString()) +
    ",\"type\":" + typeJson(expression.getType()) +
    expressionConstant(expression) + expressionOperator(expression) +
    expressionDeclaration(expression) + expressionCallee(expression) +
    expressionStorage(expression) + allocationSizeJson(expression) +
    ",\"children\":[" + concat(int position, Expr child |
      expressionChild(expression, child, position) |
      "{\"position\":" + position.toString() + ",\"id\":" + quoted(expressionKey(child)) + "}",
      "," order by position
    ) + "]}"
}
