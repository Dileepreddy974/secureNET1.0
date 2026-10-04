import pytest

from securenet.hashing import compare_hashes


def test_standard_md5_sha256_vectors_and_fixed_lengths():
    result = compare_hashes("abc", "")
    md5, sha256 = result["rows"]
    assert md5["original"] == "900150983cd24fb0d6963f7d28e17f72"
    assert md5["changed"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert sha256["original"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256["changed"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert (md5["bits"], md5["hex_characters"]) == (128, 32)
    assert (sha256["bits"], sha256["hex_characters"]) == (256, 64)
    assert result["original_hex"] == "616263" and result["changed_hex"] == ""
    assert result["original_bytes"] == 3 and result["changed_bytes"] == 0


@pytest.mark.parametrize("text", ["", "Hello", "హలో 🔒", "\x00" * 8192])
def test_identical_input_has_zero_changes(text):
    result = compare_hashes(text, text)
    assert result["identical_input"]
    assert all(row["matching"] and row["changed_bits"] == 0 for row in result["rows"])


def test_difference_count_is_bits_not_hex_characters():
    result = compare_hashes("Hello", "hello")
    assert not result["identical_input"]
    for row in result["rows"]:
        original_binary = f'{int(row["original"], 16):0{row["bits"]}b}'
        changed_binary = f'{int(row["changed"], 16):0{row["bits"]}b}'
        assert row["changed_bits"] == sum(a != b for a, b in zip(original_binary, changed_binary))
        assert 0 < row["changed_bits"] <= row["bits"]


def test_unicode_bytes_preserved_and_limits_apply_to_both_inputs():
    result = compare_hashes("é", "e\u0301")
    assert result["original_hex"] == "c3a9"
    assert result["changed_hex"] == "65cc81"
    assert not result["identical_input"]  # no hidden normalization
    assert all(not row["matching"] for row in result["rows"])
    assert len(compare_hashes("x" * 8192, "")['original_hex']) == 128
    for a, b in (("x" * 8193, ""), ("", "🔒" * 2049)):
        with pytest.raises(ValueError, match="8 KiB"):
            compare_hashes(a, b)
