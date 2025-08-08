# EVTX Zig Parser TODO

- [ ] BinXML tokens framework
  - [ ] Implement element stack and 0x02/0x03/0x04 handling
  - [ ] Implement has-more flag 0x40 for applicable tokens
- [ ] Names and attributes
  - [ ] Inline names and name-offset variants; hash ignored
  - [ ] Attribute list padding/align quirks
- [ ] Content
  - [ ] Value tokens (0x05/0x45) concat; full UTF-16LE -> UTF-8
  - [ ] Character (0x08/0x48) and Entity references (0x09/0x49)
  - [ ] CDATA (0x07/0x47)
  - [ ] PI target (0x0a) and data (0x0b)
- [ ] Substitutions
  - [ ] Normal (0x0d) and Optional (0x0e), arrays (0x80), NULL
  - [ ] SizeT with hex types, Binary XML type (0x21)
- [ ] Template system
  - [ ] Template definitions (non-contiguous), GUID mapping
  - [ ] Template instances (descriptors + values) and application
- [ ] Types and encodings
  - [ ] GUID, FILETIME, SystemTime, SID, Binary; ints/reals/hex/size/arrays
  - [ ] Exact XML/JSON representations per evtx_dump
- [ ] Output parity
  - [ ] XML whitespace/ordering/escaping parity with evtx_dump
  - [ ] JSON/JSONL shape parity from token tree
- [ ] Tests
  - [ ] Unit tests for tokens, names, attributes, substitutions, templates
  - [ ] Golden tests vs `evtx_dump` for XML and JSON/JSONL


