"""Graduated-response primitives shared by the controller, native lab and model.

TokenBucket is the policer that FlowGuard itself runs in the native gateway
and the simulation; in the SDN lab the same parameters are handed to an
OpenFlow 1.3 meter and Open vSwitch does the policing.
"""


class TokenBucket:
    """Classic token bucket: `rate_pps` tokens per second, at most `burst` stored."""

    def __init__(self, rate_pps, burst, now):
        if rate_pps <= 0:
            raise ValueError("rate_pps must be positive")
        if burst < 0:
            raise ValueError("burst must not be negative")
        self.rate_pps = float(rate_pps)
        # A zero burst still has to admit one packet at a time.
        self.capacity = max(float(burst), 1.0)
        self._tokens = self.capacity
        self._updated = now

    def _refill(self, now):
        elapsed = now - self._updated
        if elapsed > 0:  # A clock that steps backwards never adds tokens.
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_pps)
            self._updated = now

    def tokens(self, now):
        self._refill(now)
        return self._tokens

    def allow(self, now, cost=1.0):
        self._refill(now)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


class OffenderHistory:
    """Exponential back-off of the mitigation timeout for repeat offenders.

    The n-th offense inside `memory_s` of the previous rule ending gets
    min(base * factor**(n-1), max_timeout_s) seconds. With back-off disabled
    the timeout stays at the base value but offenses are still counted, which
    the graduated policy uses.
    """

    def __init__(self, base_timeout_s, factor=2.0, max_timeout_s=80, memory_s=120.0, enabled=False):
        self.base_timeout_s = int(base_timeout_s)
        self.factor = float(factor)
        self.max_timeout_s = max(int(max_timeout_s), self.base_timeout_s)
        self.memory_s = float(memory_s)
        self.enabled = bool(enabled)
        self._history = {}  # source -> (offense count, time the last rule ends)

    @classmethod
    def from_config(cls, config):
        backoff = config["mitigation"]["backoff"]
        return cls(config["mitigation_hard_timeout_s"], backoff["factor"], backoff["max_timeout_s"],
                   backoff["memory_s"], backoff["enabled"])

    def forget_expired(self, now):
        for source, (_, ends) in list(self._history.items()):
            if now - ends > self.memory_s:
                del self._history[source]

    def offense_count(self, source):
        return self._history.get(source, (0, None))[0]

    def next_offense(self, source, now):
        """Record a new offense and return (offense number, timeout in seconds)."""
        self.forget_expired(now)
        count = self.offense_count(source) + 1
        if self.enabled:
            timeout = min(self.max_timeout_s, round(self.base_timeout_s * self.factor ** (count - 1)))
        else:
            timeout = self.base_timeout_s
        self._history[source] = (count, now + timeout)
        return count, int(timeout)


def choose_action(action, offense_count, graduated_drop_after=2):
    """Map the configured policy and the offense number to "drop" or "rate_limit"."""
    if action == "drop":
        return "drop"
    if action == "rate_limit":
        return "rate_limit"
    if action == "graduated":
        return "drop" if offense_count >= graduated_drop_after else "rate_limit"
    raise ValueError(f"unknown mitigation action: {action}")
