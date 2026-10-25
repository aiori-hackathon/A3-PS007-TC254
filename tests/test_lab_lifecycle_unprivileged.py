import pytest
from network.unprivileged_runner import UnprivilegedLabRunner

@pytest.mark.skipif(not UnprivilegedLabRunner.is_supported(), reason="User namespaces not supported on this host")
def test_unprivileged_lab_creation_and_ping():
    runner = UnprivilegedLabRunner()

    # Commands to execute inside the isolated lab session:
    # 1. Verify all 5 device namespaces exist
    # 2. Warm up and ping from p6g-iot1 (2001:db8:6::11) to p6g-iot2 (2001:db8:6::12)
    # 3. Ping from p6g-iot5 (2001:db8:6::15) to p6g-router (2001:db8:6::1)
    test_script = """
echo "=== NAMESPACES ==="
ip netns list

echo "=== PING IOT1 -> IOT2 ==="
ip netns exec p6g-iot1 ping -6 -c 1 -W 1 2001:db8:6::12 >/dev/null 2>&1 || true
ip netns exec p6g-iot1 ping -6 -c 2 -W 2 2001:db8:6::12

echo "=== PING IOT5 -> ROUTER ==="
ip netns exec p6g-iot5 ping -6 -c 1 -W 1 2001:db8:6::1 >/dev/null 2>&1 || true
ip netns exec p6g-iot5 ping -6 -c 2 -W 2 2001:db8:6::1
"""
    returncode, stdout, stderr = runner.run_isolated_command(test_script, timeout=15)
    
    assert returncode == 0, f"Lab execution failed: {stderr}\nStdout: {stdout}"
    assert "p6g-iot1" in stdout
    assert "p6g-iot2" in stdout
    assert "p6g-iot3" in stdout
    assert "p6g-iot4" in stdout
    assert "p6g-iot5" in stdout
    assert "p6g-router" in stdout
    assert "64 bytes from 2001:db8:6::12" in stdout
    assert "64 bytes from 2001:db8:6::1" in stdout
