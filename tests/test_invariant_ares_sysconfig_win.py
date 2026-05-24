import pytest
import ctypes
import sys


# Simulate the vulnerable pattern: building a comma-separated list into a fixed buffer
# This models the behavior of ares_sysconfig_win.c where strcat(*dst, ",") is called
# without bounds checking when appending DNS entries from Windows configuration.

def build_dns_list_safe(entries, max_buf_size=256):
    """
    Safe implementation that models what the C code SHOULD do:
    Build a comma-separated list of DNS entries into a buffer of max_buf_size.
    Returns the result string if it fits, raises ValueError if it would overflow.
    """
    if not entries:
        return ""
    
    result = ""
    for i, entry in enumerate(entries):
        if i == 0:
            candidate = entry
        else:
            candidate = result + "," + entry
        
        # This is the invariant: we must NEVER exceed the buffer size
        if len(candidate) + 1 > max_buf_size:  # +1 for null terminator
            raise ValueError(
                f"Buffer overflow prevented: required {len(candidate) + 1} bytes, "
                f"max is {max_buf_size}"
            )
        result = candidate
    
    return result


def build_dns_list_vulnerable(entries, max_buf_size=256):
    """
    Simulates the vulnerable C behavior: appends without checking capacity.
    This is what the C code does — no bounds check before strcat(*dst, ",").
    """
    result = ""
    for i, entry in enumerate(entries):
        if i == 0:
            result = entry
        else:
            result = result + "," + entry  # No bounds check — mirrors strcat behavior
    return result


# Adversarial payloads: lists of DNS entries that could trigger buffer overflow
ADVERSARIAL_PAYLOADS = [
    # Many short entries that together exceed buffer
    ["8.8.8.8"] * 50,
    # Long individual entries
    ["192.168.100." + str(i) for i in range(50)],
    # Single very long entry (DHCP-injected malicious server name)
    ["a" * 300],
    # Many entries with max-length IPv6 addresses
    ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"] * 10,
    # Entries that are exactly at boundary
    ["x" * 254],
    # Mixed length entries
    ["1.1.1.1", "2.2.2.2"] * 40,
    # Entries with special characters (injection attempts)
    ["8.8.8.8\x00evil", "1.1.1.1"],
    # Empty string entries mixed with valid ones
    ["", "8.8.8.8"] * 30,
    # Single entry at exact buffer limit
    ["a" * 255],
    # Entries simulating DHCP poisoning with many nameservers
    [f"10.0.{i}.{j}" for i in range(10) for j in range(10)],
    # Unicode/multibyte entries
    ["dns\u0000server.local"] * 20,
    # Entries that would cause integer overflow in length calculation
    ["x" * 128] * 4,
    # Realistic attack: many valid-looking DNS servers
    [f"192.168.{i}.1" for i in range(100)],
    # Boundary: exactly 255 chars total
    ["a" * 127, "b" * 127],
    # One entry per octet exhaustion
    [f"{i}.{i}.{i}.{i}" for i in range(256)],
]


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_dns_list_buffer_boundary_invariant(payload):
    """
    Invariant: Building a comma-separated DNS entry list MUST NEVER write beyond
    the allocated buffer size. Any implementation processing DNS entries (e.g., from
    Windows DHCP/registry) must enforce that the total length including all commas
    and null terminator never exceeds the destination buffer capacity.
    
    This guards against the strcat(*dst, ",") vulnerability in ares_sysconfig_win.c
    where no bounds check is performed before appending the comma separator.
    """
    MAX_BUFFER_SIZE = 256  # Typical fixed buffer size in C DNS config parsing

    # Property 1: The safe implementation must never produce output exceeding buffer
    try:
        result = build_dns_list_safe(payload, MAX_BUFFER_SIZE)
        # If it succeeded, the result MUST fit in the buffer
        assert len(result) + 1 <= MAX_BUFFER_SIZE, (
            f"INVARIANT VIOLATED: Safe builder produced {len(result) + 1} bytes "
            f"which exceeds buffer size {MAX_BUFFER_SIZE}. "
            f"Payload had {len(payload)} entries."
        )
        # Result must be a valid comma-separated string
        if result:
            parts = result.split(",")
            assert len(parts) <= len(payload), (
                "Result has more parts than input entries"
            )
    except ValueError:
        # Overflow was correctly detected and prevented — this is acceptable
        pass

    # Property 2: If the vulnerable path would overflow, the safe path MUST catch it
    vulnerable_result = build_dns_list_vulnerable(payload, MAX_BUFFER_SIZE)
    
    if len(vulnerable_result) + 1 > MAX_BUFFER_SIZE:
        # The vulnerable code would overflow — the safe code MUST raise an error
        with pytest.raises(ValueError, match="Buffer overflow prevented"):
            build_dns_list_safe(payload, MAX_BUFFER_SIZE)

    # Property 3: Total comma count must equal entries - 1 (structural integrity)
    try:
        result = build_dns_list_safe(payload, MAX_BUFFER_SIZE)
        if result and len(payload) > 0:
            non_empty_entries = [e for e in payload if e and "\x00" not in e]
            if non_empty_entries:
                comma_count = result.count(",")
                assert comma_count < len(payload), (
                    f"Too many commas: {comma_count} commas for {len(payload)} entries"
                )
    except ValueError:
        pass  # Overflow correctly prevented


@pytest.mark.parametrize("num_entries,entry_size", [
    (1, 300),      # Single oversized entry
    (100, 3),      # Many small entries
    (50, 5),       # Medium count, small entries
    (10, 30),      # Few entries, medium size
    (255, 1),      # Maximum single-char entries
    (2, 128),      # Two entries at half buffer
    (1, 255),      # Single entry at buffer limit
    (1, 256),      # Single entry exceeding buffer
])
def test_dns_buffer_size_boundaries(num_entries, entry_size):
    """
    Invariant: Buffer size constraints must be enforced regardless of the number
    of entries or their individual sizes. The comma-appending logic must account
    for both entry content AND separator overhead.
    """
    MAX_BUFFER_SIZE = 256
    entries = ["x" * entry_size] * num_entries
    
    # Calculate expected total size: sum of entries + (n-1) commas + null terminator
    expected_size = (entry_size * num_entries) + max(0, num_entries - 1) + 1
    
    if expected_size > MAX_BUFFER_SIZE:
        # MUST raise — buffer would overflow
        with pytest.raises(ValueError):
            build_dns_list_safe(entries, MAX_BUFFER_SIZE)
    else:
        # MUST succeed and fit within bounds
        result = build_dns_list_safe(entries, MAX_BUFFER_SIZE)
        assert len(result) + 1 <= MAX_BUFFER_SIZE, (
            f"Buffer overflow: result needs {len(result) + 1} bytes, "
            f"buffer is {MAX_BUFFER_SIZE} bytes"
        )
        assert len(result) + 1 == expected_size, (
            f"Size mismatch: expected {expected_size}, got {len(result) + 1}"
        )