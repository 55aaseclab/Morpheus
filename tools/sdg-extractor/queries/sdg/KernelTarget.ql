import cpp

from Macro macro
where macro.getName().regexpMatch(".*(BYTE_ORDER|ENDIAN).*|__AARCH64EB__|__ARMEB__")
select macro.getName() as name, macro.getBody() as value
