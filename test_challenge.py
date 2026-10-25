from sentinel.challenge import ChallengeManager, solve
from sentinel.config import Settings

S = Settings(challenge_difficulty_bits=8, challenge_ttl_s=60, pass_ttl_s=60, secret="k")


def test_roundtrip_and_replay():
    m = ChallengeManager(S)
    ch = m.issue("1.1.1.1", now=1000)
    sol = str(solve(ch.token, ch.difficulty_bits))
    assert m.verify("1.1.1.1", ch.token, sol, now=1001)
    assert not m.verify("1.1.1.1", ch.token, sol, now=1002)  # replay


def test_rejects_wrong_ip_expiry_bad_solution_tamper():
    m = ChallengeManager(S)
    ch = m.issue("1.1.1.1", now=1000)
    sol = str(solve(ch.token, ch.difficulty_bits))
    assert not m.verify("2.2.2.2", ch.token, sol, now=1001)
    assert not m.verify("1.1.1.1", ch.token, sol, now=5000)
    tampered = ch.token[:-1] + ("0" if ch.token[-1] != "0" else "1")
    assert not m.verify("1.1.1.1", tampered, sol, now=1001)


def test_pass_cookie():
    m = ChallengeManager(S)
    c = m.issue_pass("1.1.1.1", now=1000)
    assert m.check_pass("1.1.1.1", c, now=1010)
    assert not m.check_pass("2.2.2.2", c, now=1010)
    assert not m.check_pass("1.1.1.1", c, now=2000)
    assert not m.check_pass("1.1.1.1", "garbage")


def test_insufficient_work_rejected():
    m = ChallengeManager(Settings(challenge_difficulty_bits=20, secret="k"))
    ch = m.issue("1.1.1.1", now=1000)
    assert not m.verify("1.1.1.1", ch.token, "0", now=1001)  # 1-in-a-million to pass by luck
