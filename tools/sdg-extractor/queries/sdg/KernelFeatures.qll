import KernelFacts

predicate registeredDriver(Variable driver, Function probe, Variable table) {
  exists(ClassAggregateLiteral initializer, Field probeField, Field tableField,
         FunctionAccess callback, VariableAccess reference |
    initializer = driver.getInitializer().getExpr() and
    probeField.getName() = "probe" and tableField.getName() = "feature_table" and
    callback = initializer.getAFieldExpr(probeField).getUnconverted() and
    probe = callback.getTarget() and
    reference = initializer.getAFieldExpr(tableField).getUnconverted() and
    table = reference.getTarget()
  )
}

predicate registeredFeatureGetter(Variable operations, Function getter) {
  exists(ClassAggregateLiteral initializer, Field field, FunctionAccess callback |
    initializer = operations.getInitializer().getExpr() and
    field.getName() = "get_features" and
    callback = initializer.getAFieldExpr(field).getUnconverted() and
    getter = callback.getTarget()
  )
}

string driverFeaturesJson(Variable table) {
  result = "[" + concat(int bit |
    exists(ArrayAggregateLiteral initializer, Expr element |
      initializer = table.getInitializer().getExpr() and
      element = initializer.getAnElementExpr(_) and
      bit = element.getValue().toInt()
    ) | bit.toString(), "," order by bit) + "]"
}
