import KernelDma

predicate pageDmaSource(Expr read, FunctionCall mapping, FunctionCall completion, FunctionCall view) {
  exists(Expr page, Expr offset, Expr size, Expr direction, Expr handle, Expr completedDirection,
         Expr viewedPage, Expr address, DataFlow::Node pageOrigin, DataFlow::Node mappedPage,
         DataFlow::Node viewedPageNode, DataFlow::Node mappedHandle, DataFlow::Node completedHandle,
         DataFlow::Node pageAddress, DataFlow::Node readAddress |
    dmaPageMapping(mapping, page, offset, size, direction) and deviceWritableDirection(direction) and
    dmaCompletion(completion, handle, completedDirection) and deviceWritableDirection(completedDirection) and
    pageAddressView(view, viewedPage) and scalarMemoryRead(read, address, _) and
    mappedPage.asExpr() = page and viewedPageNode.asExpr() = viewedPage and
    DmaAddressFlow::flow(pageOrigin, mappedPage) and DmaAddressFlow::flow(pageOrigin, viewedPageNode) and
    mappedHandle.asExpr() = mapping and completedHandle.asExpr() = handle and
    DmaHandleFlow::flow(mappedHandle, completedHandle) and
    pageAddress.asExpr() = view and readAddress.asExpr().getFullyConverted() = address and
    DmaAddressFlow::flow(pageAddress, readAddress) and
    dominates(mapping, completion) and orderedOnPath(completion, read) and
    not exists(AssignExpr write, DataFlow::Node stored, DataFlow::Node loaded |
      orderedOnPath(completion, write) and dominates(write, read) and
      stored.asExpr() = write.getRValue() and loaded.asExpr() = read and DataFlow::localFlow(stored, loaded)
    )
  )
}

predicate pageDmaSourceFact(Expr read, string kind, string json) {
  exists(Expr address, int offset |
    scalarMemoryRead(read, address, offset) and pageDmaSource(read, _, _, _) and
    not dmaSource(read, _, _) and kind = "DmaReadStreaming" and
    json = "{\"kind\":\"DmaReadStreaming\",\"size_bytes\":" + read.getType().getSize().toString() +
      ",\"byte_order\":" + quoted(targetByteOrder()) +
      ",\"address\":" + quoted(expressionKey(address)) +
      ",\"field_offset\":" + offset.toString() + dmaReadIndicesJson(read) + dmaReadFieldJson(read) +
      ",\"bindings\":[" + concat(FunctionCall mapping, FunctionCall completion, FunctionCall view,
                                  Expr page, Expr mappingOffset, Expr size, Expr direction |
        pageDmaSource(read, mapping, completion, view) and dmaPageMapping(mapping, page, mappingOffset, size, direction) |
        "{\"mapping\":" + quoted(expressionKey(mapping)) +
        ",\"completion\":" + quoted(expressionKey(completion)) +
        ",\"buffer\":" + quoted(expressionKey(view)) +
        ",\"page\":" + quoted(expressionKey(page.getFullyConverted())) +
        ",\"mapping_offset\":" + quoted(expressionKey(mappingOffset.getFullyConverted())) +
        ",\"size\":" + quoted(expressionKey(size.getFullyConverted())) +
        ",\"direction\":" + quoted(expressionKey(direction.getFullyConverted())) +
        ",\"location\":" + locationJson(mapping) + "}",
        "," order by expressionKey(mapping), expressionKey(completion), expressionKey(view)) +
      "],\"function\":" + quoted(functionKey(read.getEnclosingFunction())) +
      ",\"location\":" + locationJson(read) + "}"
  )
}
