# Type stub for the subset of construct (https://construct.readthedocs.io)
# that hartip uses. construct ships no type information; this stub lets
# mypy and pyright check the call sites. Extend it when hartip starts
# using another construct name. Not shipped with the package.

from collections.abc import Callable, Mapping
from typing import Any, Generic, TypeVar

_P = TypeVar("_P")
_B = TypeVar("_B")

class Container(dict[str, Any]):
    def __getattr__(self, name: str) -> Any: ...

class Construct(Generic[_P, _B]):
    def parse(self, data: bytes, **contextkw: Any) -> _P: ...
    def build(self, obj: _B, **contextkw: Any) -> bytes: ...
    def sizeof(self, **contextkw: Any) -> int: ...
    def __rtruediv__(self, name: str) -> Construct[_P, _B]: ...

class FormatField(Construct[_P, _B]): ...

class Struct(Construct[Container, Mapping[str, Any]]):
    def __init__(self, *subcons: Construct[Any, Any], **subconskw: Construct[Any, Any]) -> None: ...

def Bytes(length: int | Callable[[Container], int]) -> Construct[bytes, bytes]: ...
def Computed(func: Callable[[Container], _P] | _P) -> Construct[_P, None]: ...
def IfThenElse(
    condfunc: Callable[[Container], bool] | bool,
    thensubcon: Construct[_P, _B],
    elsesubcon: Construct[_P, _B],
) -> Construct[_P, _B]: ...

Int8ub: FormatField[int, int]
Int16ub: FormatField[int, int]
Int32ub: FormatField[int, int]
Int64ub: FormatField[int, int]
Float32b: FormatField[float, float]

# ``this.field`` builds a context lambda; only ever passed to the
# functions above, which accept a callable.
this: Any
