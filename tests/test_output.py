from tls_audit import output


def _base_result():
    return {
        "host": "example.com",
        "port": 443,
        "ip": "1.2.3.4",
        "reachable": True,
        "certificate": None,
        "chain_valid": {"valid": True, "error": None},
        "protocols": {},
        "weak_ciphers": {},
        "negotiated": None,
        "post_quantum": {"status": "classical", "evidence": []},
        "errors": [],
    }


def test_evaluate_flags_expired_certificate():
    r = _base_result()
    r["certificate"] = {
        "expired": True,
        "days_left": -3,
        "signature_sha1": False,
        "key": {"type": "RSA", "bits": 2048, "curve": None},
    }
    fails, _ = output.evaluate(r)
    assert "certificate is expired" in fails


def test_evaluate_flags_sha1():
    r = _base_result()
    r["certificate"] = {
        "expired": False,
        "days_left": 60,
        "signature_sha1": True,
        "key": {"type": "RSA", "bits": 2048, "curve": None},
    }
    fails, _ = output.evaluate(r)
    assert any("SHA-1" in f for f in fails)


def test_evaluate_flags_tls10():
    r = _base_result()
    r["protocols"] = {"TLS 1.0": {"supported": True, "version": "TLSv1"}}
    fails, _ = output.evaluate(r)
    assert "TLS 1.0 is enabled" in fails


def test_evaluate_flags_weak_cipher():
    r = _base_result()
    r["weak_ciphers"] = {"RC4": {"accepted": True, "cipher": "RC4-SHA", "note": None}}
    fails, _ = output.evaluate(r)
    assert "RC4 cipher accepted" in fails


def test_evaluate_warns_on_classical_pq():
    r = _base_result()
    _, warns = output.evaluate(r)
    assert any("post-quantum" in w for w in warns)


def test_render_terminal_produces_output():
    r = _base_result()
    text = output.render_terminal([r])
    assert r["host"] in text
    assert "Certificate" in text
