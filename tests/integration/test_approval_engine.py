from skx_infra_guard.approval.sentinel import SentinelApprovalChannel


def test_request_then_approve_then_valid(tmp_path):
    channel = SentinelApprovalChannel(tmp_path)
    req = channel.request(
        rule_id="k8s.delete.namespace",
        resource="ns/legacy",
        requester="alejandro.gonzalezr@skydropx.com",
        reason="one-off cleanup",
    )
    assert not channel.has_valid_approval(
        rule_id="k8s.delete.namespace", resource="ns/legacy", requester="alejandro.gonzalezr@skydropx.com"
    )

    channel.approve(req.request_id, approver="juanma.maffei@skydropx.com")

    assert channel.has_valid_approval(
        rule_id="k8s.delete.namespace", resource="ns/legacy", requester="alejandro.gonzalezr@skydropx.com"
    )


def test_expired_approval_is_not_valid(tmp_path):
    channel = SentinelApprovalChannel(tmp_path)
    req = channel.request(
        rule_id="r1", resource="res1", requester="u1", reason="x", ttl_seconds=0
    )
    channel.approve(req.request_id, approver="approver1")
    import time

    time.sleep(0.01)
    assert not channel.has_valid_approval(rule_id="r1", resource="res1", requester="u1")


def test_different_requester_does_not_inherit_approval(tmp_path):
    channel = SentinelApprovalChannel(tmp_path)
    req = channel.request(rule_id="r1", resource="res1", requester="u1", reason="x")
    channel.approve(req.request_id, approver="approver1")
    assert not channel.has_valid_approval(rule_id="r1", resource="res1", requester="u2")
