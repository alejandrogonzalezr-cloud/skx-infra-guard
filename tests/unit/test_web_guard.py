from skx_infra_guard.core.decision import Decision, EnvironmentTier
from skx_infra_guard.domains import web_guard


def test_cloud_metadata_blocked():
    v = web_guard.evaluate("http://169.254.169.254/latest/meta-data/", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_gcp_metadata_blocked():
    v = web_guard.evaluate("http://metadata.google.internal/computeMetadata/v1/", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_localhost_blocked():
    v = web_guard.evaluate("http://localhost:8080/admin", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_rfc1918_10_x_blocked():
    v = web_guard.evaluate("http://10.0.0.1/admin", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_rfc1918_192_168_blocked():
    v = web_guard.evaluate("http://192.168.1.1/", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_file_uri_blocked():
    v = web_guard.evaluate("file:///etc/passwd", EnvironmentTier.DEV)
    assert v is not None and v.decision == Decision.BLOCK


def test_public_https_url_is_fine():
    assert web_guard.evaluate("https://api.github.com/repos", EnvironmentTier.DEV) is None
