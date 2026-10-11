import KernelMmio

from FunctionCall read
where ioRead(read, _) and not ioHelper(read.getEnclosingFunction())
select locationKey(read) as location, read.getEnclosingFunction().getName() as function,
  concat(Expr root | mmioReadRoot(read, root) | expressionKey(root), ";") as roots,
  concat(FunctionCall write | mmioWriteContext(read, write) | locationKey(write), ";") as preceding_writes,
  mmioMappingsJson(read) as bindings
