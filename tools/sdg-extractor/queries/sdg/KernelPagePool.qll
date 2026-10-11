import KernelPages

private predicate implementationCall(Function function, FunctionCall call) {
  call.getEnclosingFunction() = function
  or
  exists(FunctionCall nested |
    nested.getEnclosingFunction() = function and exists(nested.getTarget().getBlock()) and
    implementationCall(nested.getTarget(), call)
  )
}

predicate pagePoolImplementation(Function function, FunctionCall addressGetter, FunctionCall synchronization) {
  addressGetter.getEnclosingFunction() = function and
  addressGetter.getTarget().getName() = "page_pool_get_dma_addr" and
  DataFlow::localFlow(DataFlow::parameterNode(function.getParameter(1)), DataFlow::exprNode(addressGetter.getArgument(0))) and
  implementationCall(function, synchronization) and
  synchronization.getTarget().getName() = "dma_sync_single_range_for_cpu" and
  exists(DataFlow::Node handle, DataFlow::Node synchronizedHandle |
    handle.asExpr() = addressGetter and synchronizedHandle.asExpr() = synchronization.getArgument(1) and
    DmaHandleFlow::flow(handle, synchronizedHandle)
  )
}

predicate pagePoolSource(Expr read, FunctionCall completion, Expr cpuView) {
  exists(Expr address, FunctionCall getter, FunctionCall synchronization |
    pagePoolSyncCall(completion) and
    pagePoolImplementation(completion.getTarget(), getter, synchronization) and
    scalarMemoryRead(read, address, _) and orderedOnPath(completion, read) and
    (
      exists(FunctionCall view, Expr page, DataFlow::Node origin, DataFlow::Node completedPage,
             DataFlow::Node viewedPage, DataFlow::Node pointer, DataFlow::Node readPointer |
        pageAddressView(view, page) and cpuView = view and
        completedPage.asExpr() = completion.getArgument(1) and viewedPage.asExpr() = page and
        DmaAddressFlow::flow(origin, completedPage) and DmaAddressFlow::flow(origin, viewedPage) and
        pointer.asExpr() = view and readPointer.asExpr().getFullyConverted() = address and
        DmaAddressFlow::flow(pointer, readPointer)
      )
      or
      exists(FunctionCall view, DataFlow::Node origin, DataFlow::Node viewedAddress,
             DataFlow::Node readAddress, DataFlow::Node page, DataFlow::Node completedPage |
        inversePageView(view, cpuView) and
        page.asExpr() = view and completedPage.asExpr() = completion.getArgument(1) and
        DmaAddressFlow::flow(page, completedPage) and
        viewedAddress.asExpr() = cpuView and readAddress.asExpr().getFullyConverted() = address and
        DmaAddressFlow::flow(origin, viewedAddress) and DmaAddressFlow::flow(origin, readAddress)
      )
    ) and
    not exists(AssignExpr write, DataFlow::Node stored, DataFlow::Node loaded |
      orderedOnPath(completion, write) and dominates(write, read) and
      stored.asExpr() = write.getRValue() and loaded.asExpr() = read and DataFlow::localFlow(stored, loaded)
    )
  )
}

predicate pagePoolSourceFact(Expr read, string kind, string json) {
  exists(Expr address, int offset |
    scalarMemoryRead(read, address, offset) and pagePoolSource(read, _, _) and
    not dmaSource(read, _, _) and not pageDmaSource(read, _, _, _) and
    kind = "DmaReadStreaming" and
    json = "{\"kind\":\"DmaReadStreaming\",\"size_bytes\":" + read.getType().getSize().toString() +
      ",\"byte_order\":" + quoted(targetByteOrder()) +
      ",\"address\":" + quoted(expressionKey(address)) +
      ",\"field_offset\":" + offset.toString() + dmaReadIndicesJson(read) + dmaReadFieldJson(read) +
      ",\"provenance_status\":\"conditional\",\"bindings\":[" + concat(FunctionCall completion, Expr view |
        pagePoolSource(read, completion, view) |
        "{\"observation\":" + quoted(expressionKey(completion)) +
        ",\"completion\":" + quoted(expressionKey(completion)) +
        ",\"buffer\":" + quoted(expressionKey(view.getFullyConverted())) +
        ",\"pool\":" + quoted(expressionKey(completion.getArgument(0).getFullyConverted())) +
        ",\"page\":" + quoted(expressionKey(completion.getArgument(1).getFullyConverted())) +
        ",\"sync_offset\":" + quoted(expressionKey(completion.getArgument(2).getFullyConverted())) +
        ",\"size\":" + quoted(expressionKey(completion.getArgument(3).getFullyConverted())) +
        ",\"unresolved_requirements\":[\"pool was created with PP_FLAG_DMA_MAP\",\"page belongs to this pool\",\"pool direction permits device writes\",\"pool offset and live mapping require binding\"]," +
        "\"location\":" + locationJson(completion) + "}",
        "," order by expressionKey(completion), expressionKey(view)) +
      "],\"function\":" + quoted(functionKey(read.getEnclosingFunction())) +
      ",\"location\":" + locationJson(read) + "}"
  )
}
