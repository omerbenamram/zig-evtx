"""
evtxzig - Fast EVTX parser with Python bindings.

This module provides efficient parsing of Windows Event Log (.evtx) files
using a Zig-based parser with Python bindings.

Example usage:
    >>> import evtxzig
    >>> for record in evtxzig.iter_records('System.evtx'):
    ...     print(record)

Functions:
    iter_records: Iterate over records from a file path
    iter_records_from_bytes: Iterate over records from bytes
    dump_file_bytes: Parse entire file and return as string
    dump_file_to_file: Parse file and write output to another file
"""

from ._lib import dump_file_bytes, dump_file_to_file  # noqa: F401
from ._lib import Iter as _Iter


class _RecordIterator:
    """Wrapper that holds a reference to the underlying native iterator.

    IMPORTANT: This wrapper exists to work around a pydust/Python GC timing bug.

    ## The Problem

    When using patterns like `list(iter_records(...))` without assigning the
    iterator to a variable first, Python's garbage collector can deallocate
    the native `_Iter` object *during* the list() call, but *before* the
    returned Python string objects are fully processed. This causes heap
    corruption that manifests as segfaults when:

    - Creating large dictionaries (1000+ keys)
    - Calling json.loads() on the returned strings
    - Any operation that triggers significant memory allocation

    ## The Symptom

    ```python
    # This crashes with SIGSEGV (exit code 139):
    recs = list(iter_records('file.evtx', 'jsonl', max_records=2))
    data = json.loads(recs[0])  # <-- segfault here

    # But this works fine:
    it = iter_records('file.evtx', 'jsonl', max_records=2)
    recs = list(it)
    data = json.loads(recs[0])  # <-- OK because 'it' keeps iterator alive
    ```

    ## The Fix

    This wrapper class holds a reference to the native `_Iter` object,
    preventing premature garbage collection. The wrapper stays alive as
    long as any reference to it exists (e.g., during list() iteration).

    ## Debugging Tips

    If this issue resurfaces:

    1. Check pydust's `tp_finalize` in `pytypes.zig` (~line 324) - this is
       called when Python finalizes the object.

    2. Check pydust's `tp_iternext` (~line 280) - this handles __next__.

    3. The native iterator is in `src/evtx_pydust.zig` (IterDef struct).

    4. The implementation is in `src/evtx_pydust_impl.zig` (IterState struct).

    5. Try forcing GC with `gc.collect()` between operations - if that
       fixes the crash, it's likely a lifetime/reference counting issue.

    6. Assigning the iterator to a variable before list() is a reliable
       workaround: `it = iter_records(...); recs = list(it)`

    ## See Also

    - pydust source: .venv/lib/python3.12/site-packages/pydust/src/
    - pydust PyMemAllocator: .../pydust/src/mem.zig (uses PyMem_Malloc)
    - Python's tp_finalize docs: https://docs.python.org/3/c-api/typeobj.html
    """

    __slots__ = ("_iter",)

    def __init__(self, inner_iter):
        self._iter = inner_iter

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)


def iter_records(
    path: str,
    format: str = "xml",
    *,
    skip_first: int = 0,
    max_records: int = 0,
    validate_checksums: bool = True,
    verbosity: int = 0,
    carve: bool = False,
):
    """Iterate over EVTX records from a file.

    Args:
        path: Path to the EVTX file.
        format: Output format - 'xml' or 'jsonl' (JSON Lines).
        skip_first: Number of records to skip before yielding.
        max_records: Maximum records to yield (0 = unlimited).
        validate_checksums: Validate chunk checksums (default True).
        verbosity: Logging verbosity level (0-3).
        carve: Scan for valid chunks even with corrupted headers.
            Useful for recovering data from damaged files.

    Returns:
        Iterator[str]: Iterator yielding each record in the specified format.

    Example:
        >>> for record in evtxzig.iter_records('System.evtx', 'jsonl'):
        ...     data = json.loads(record)
        ...     print(data['Event']['System']['EventID'])
    """
    return _RecordIterator(
        _Iter(
            path,
            format,
            skip_first=skip_first,
            max_records=max_records,
            validate_checksums=validate_checksums,
            verbosity=verbosity,
            carve=carve,
        )
    )


def iter_records_from_bytes(
    data: bytes,
    format: str = "xml",
    *,
    skip_first: int = 0,
    max_records: int = 0,
    validate_checksums: bool = True,
    verbosity: int = 0,
    carve: bool = False,
):
    """Iterate over EVTX records from bytes.

    Same as iter_records() but reads from a bytes object instead of a file.
    Useful when the EVTX data is already in memory.

    Args:
        data: EVTX file contents as bytes.
        format: Output format - 'xml' or 'jsonl' (JSON Lines).
        skip_first: Number of records to skip before yielding.
        max_records: Maximum records to yield (0 = unlimited).
        validate_checksums: Validate chunk checksums (default True).
        verbosity: Logging verbosity level (0-3).
        carve: Scan for valid chunks even with corrupted headers.

    Returns:
        Iterator[str]: Iterator yielding each record in the specified format.

    Example:
        >>> with open('System.evtx', 'rb') as f:
        ...     for record in evtxzig.iter_records_from_bytes(f.read()):
        ...         print(record)
    """
    return _RecordIterator(
        _Iter.from_bytes(
            data,
            format,
            skip_first=skip_first,
            max_records=max_records,
            validate_checksums=validate_checksums,
            verbosity=verbosity,
            carve=carve,
        )
    )


__all__ = [
    "iter_records",
    "iter_records_from_bytes",
    "dump_file_bytes",
    "dump_file_to_file",
]
