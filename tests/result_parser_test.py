"""Unit tests for result_parser module."""

from agent import result_parser


def testNormalizeNameServers_whenMixedCaseAndDuplicates_returnsLowercaseUnique() -> None:
    """Test that mixed-case name servers are lowercased and deduplicated."""
    name_servers = [
        "Ns1.example.COM",
        "ns1.example.com",
        "NS2.example.COM",
        "ns2.example.com",
    ]

    normalized = result_parser._normalize_name_servers(name_servers)

    assert normalized == ["ns1.example.com", "ns2.example.com"]


def testNormalizeNameServers_whenAlreadyNormalized_returnsSame() -> None:
    """Test that already normalized name servers are returned unchanged."""
    name_servers = ["ns1.example.com", "ns2.example.com"]

    normalized = result_parser._normalize_name_servers(name_servers)

    assert normalized == ["ns1.example.com", "ns2.example.com"]


def testNormalizeNameServers_whenEmptyList_returnsEmpty() -> None:
    """Test that an empty list returns an empty list."""
    normalized = result_parser._normalize_name_servers([])

    assert normalized == []
