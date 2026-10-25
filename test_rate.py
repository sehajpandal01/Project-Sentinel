from sentinel.config import Settings
from sentinel.detectors.rate import AdaptiveRateDetector
from sentinel.models import Action
from tests.helpers import make_ctx

S = Settings(rate_window_s=10, rate_min_threshold=20, rate_sample_interval_s=1,
             rate_min_samples=10, rate_k_sigma=3.0, secret="t")


async def feed(det, ip, ts, n):
    last = None
    for i in range(n):
        last = await det.inspect(make_ctx(ip=ip, ts=ts + i * 0.001))
    return last


async def test_floor_before_baseline():
    det = AdaptiveRateDetector(S)
    assert det.threshold == 20
    v = await feed(det, "9.9.9.9", 0.0, 25)
    assert v and v.action is Action.CHALLENGE


async def test_threshold_adapts_up_with_busier_baseline():
    det = AdaptiveRateDetector(S)
    t = 0.0
    for _ in range(15):  # 15 seconds of busy-but-normal users (~30 req/window each)
        for u in range(8):
            for i in range(3):
                await det.inspect(make_ctx(ip=f"10.0.0.{u}", ts=t + i * 0.01))
        t += 1.0
    assert det.threshold > 20, det.threshold


async def test_hard_block_and_pass_exemption():
    det = AdaptiveRateDetector(S)
    v = await feed(det, "8.8.8.8", 0.0, 100)
    assert v and v.action is Action.BLOCK
    det2 = AdaptiveRateDetector(S)
    for i in range(30):
        v = await det2.inspect(make_ctx(ip="7.7.7.7", ts=i * 0.001, has_pass=True))
    assert v is None  # over soft threshold but holds a solved challenge


async def test_flooder_excluded_from_baseline():
    det = AdaptiveRateDetector(S)
    t = 0.0
    for _ in range(12):
        await feed(det, "6.6.6.6", t, 200)
        await det.inspect(make_ctx(ip="1.2.3.4", ts=t))
        t += 1.0
    assert max(det._baseline, default=0) <= det.threshold + 1  # flood never entered baseline
