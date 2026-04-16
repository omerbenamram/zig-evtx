"""Tests for evtxzig Python bindings."""

import json
import pytest

import evtxzig

SAMPLE_FILE = "samples/system.evtx"


class TestIterRecords:
    """Tests for iter_records function."""

    def test_iter_records_xml(self):
        """Basic XML iteration works."""
        records = list(evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=3))
        assert len(records) == 3
        for rec in records:
            assert rec.startswith("<Event")
            assert "</Event>" in rec

    def test_iter_records_jsonl(self):
        """JSON Lines iteration works and produces valid JSON."""
        records = list(evtxzig.iter_records(SAMPLE_FILE, "jsonl", max_records=3))
        assert len(records) == 3
        for rec in records:
            data = json.loads(rec)
            assert "Event" in data
            assert "System" in data["Event"]

    def test_iter_records_inline_for_loop(self):
        """Iteration works directly in for loop (regression test)."""
        count = 0
        for rec in evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=5):
            count += 1
            assert "<Event" in rec
        assert count == 5

    def test_iter_records_with_enumerate(self):
        """Iteration works with enumerate (regression test)."""
        found = []
        for i, rec in enumerate(
            evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=3)
        ):
            found.append((i, len(rec)))
        assert len(found) == 3
        assert found[0][0] == 0
        assert found[1][0] == 1
        assert found[2][0] == 2

    def test_iter_records_skip_first(self):
        """skip_first option works."""
        all_records = list(evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=5))
        skipped = list(
            evtxzig.iter_records(SAMPLE_FILE, "xml", skip_first=2, max_records=3)
        )
        assert len(skipped) == 3
        assert skipped[0] == all_records[2]

    def test_iter_records_max_records(self):
        """max_records limits output."""
        records = list(evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=10))
        assert len(records) == 10

    def test_iter_records_all(self):
        """Can iterate all records in file."""
        records = list(evtxzig.iter_records(SAMPLE_FILE, "xml"))
        assert len(records) > 100  # system.evtx has 326 records


class TestIterRecordsFromBytes:
    """Tests for iter_records_from_bytes function."""

    def test_from_bytes_xml(self):
        """Reading from bytes works."""
        with open(SAMPLE_FILE, "rb") as f:
            data = f.read()
        records = list(evtxzig.iter_records_from_bytes(data, "xml", max_records=3))
        assert len(records) == 3
        for rec in records:
            assert "<Event" in rec

    def test_from_bytes_matches_file(self):
        """Reading from bytes produces same output as from file."""
        with open(SAMPLE_FILE, "rb") as f:
            data = f.read()
        from_file = list(evtxzig.iter_records(SAMPLE_FILE, "xml", max_records=5))
        from_bytes = list(evtxzig.iter_records_from_bytes(data, "xml", max_records=5))
        assert from_file == from_bytes


class TestDumpFunctions:
    """Tests for dump_file_bytes and dump_file_to_file."""

    def test_dump_file_bytes_xml(self):
        """dump_file_bytes returns XML content."""
        result = evtxzig.dump_file_bytes(SAMPLE_FILE, "xml")
        assert isinstance(result, str)
        assert "<Event" in result
        assert result.count("<Event") > 100

    def test_dump_file_bytes_jsonl(self):
        """dump_file_bytes returns JSON Lines content."""
        result = evtxzig.dump_file_bytes(SAMPLE_FILE, "jsonl")
        lines = [l for l in result.strip().split("\n") if l]
        assert len(lines) > 100
        # Each line should be valid JSON
        for line in lines[:5]:
            data = json.loads(line)
            assert "Event" in data

    def test_dump_file_to_file(self, tmp_path):
        """dump_file_to_file writes output correctly."""
        out_path = tmp_path / "output.xml"
        evtxzig.dump_file_to_file(SAMPLE_FILE, str(out_path), "xml")
        content = out_path.read_text()
        assert "<Event" in content
        assert content.count("<Event") > 100


class TestErrorHandling:
    """Tests for error cases."""

    def test_invalid_path(self):
        """Invalid file path raises error."""
        with pytest.raises(Exception):
            list(evtxzig.iter_records("/nonexistent/file.evtx", "xml"))

    def test_invalid_format(self):
        """Invalid format raises error."""
        with pytest.raises(Exception):
            list(evtxzig.iter_records(SAMPLE_FILE, "invalid_format"))
