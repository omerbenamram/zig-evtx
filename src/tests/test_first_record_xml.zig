const std = @import("std");
const testing = std.testing;
const evtx = @import("../evtx.zig");


/// Reference XML for the first record obtained from the Python parser.
const reference_xml =
    "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\"></Provider>\n" ++
    "<EventID Qualifiers=\"\">4608</EventID>\n" ++
    "<Version>0</Version>\n" ++
    "<Level>0</Level>\n" ++
    "<Task>12288</Task>\n" ++
    "<Opcode>0</Opcode>\n" ++
    "<Keywords>0x8020000000000000</Keywords>\n" ++
    "<TimeCreated SystemTime=\"2016-07-08 18:12:51.681641+00:00\"></TimeCreated>\n" ++
    "<EventRecordID>1</EventRecordID>\n" ++
    "<Correlation ActivityID=\"\" RelatedActivityID=\"\"></Correlation>\n" ++
    "<Execution ProcessID=\"456\" ThreadID=\"460\"></Execution>\n" ++
    "<Channel>Security</Channel>\n" ++
    "<Computer>37L4247F27-25</Computer>\n" ++
    "<Security UserID=\"\"></Security>\n" ++
    "</System>\n" ++
    "<EventData></EventData>\n" ++
    "</Event>\n";

test "First record XML matches Python" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var parser = evtx.Evtx.init(allocator);
    defer parser.deinit();
    try parser.open("tests/data/security.evtx");

    var record_iter = parser.records();
    const first = record_iter.next() orelse return error.TestUnexpected;
    const zig_xml = try first.xml(allocator);
    defer allocator.free(zig_xml);

    const py_xml = reference_xml;

    std.log.debug("Zig XML length: {d}", .{zig_xml.len});
    std.log.debug("Python XML length: {d}", .{py_xml.len});

    try testing.expectEqualStrings(py_xml, zig_xml);
}
