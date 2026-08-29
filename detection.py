import math
from collections import deque
from models import Status, PHYSIO_BOUNDS, SENSOR_UNITS


class ClusterHead:
    """Fast, local statistical check per sensor: keeps the last WINDOW
    readings and flags anything too many standard deviations away from
    their rolling mean -- the device-level counterpart of the paper's
    Sensor Agent."""

    WINDOW = 15
    Z_THRESHOLD = 3

    def __init__(self):
        self.history = {}          # sensor_id -> deque of recent values
        self.last_seen_tick = {}

    def _window(self, sensor_id):
        if sensor_id not in self.history:
            self.history[sensor_id] = deque(maxlen=self.WINDOW)
        return self.history[sensor_id]

    def local_check(self, pkt):
        """Returns True if this reading looks like a local statistical
        outlier compared to this sensor's own recent history."""
        window = self._window(pkt.sensor_id)
        suspicious = False
        if len(window) >= 5:
            mean = sum(window) / len(window)
            var = sum((v - mean) ** 2 for v in window) / len(window)
            sd = math.sqrt(var) or 0.01
            z = abs(pkt.value - mean) / sd
            suspicious = z > self.Z_THRESHOLD
        window.append(pkt.value)
        self.last_seen_tick[pkt.sensor_id] = pkt.timestamp
        return suspicious


class DetectiveAgent:
    """Three explicit, deterministic rule checks (if/else logic, NOT a
    trained classifier):
        1. Physiological bound check           -> Data Injection/Fabrication
        2. Duplicate-timestamp signature check  -> Replay Attack
        3. Data-arrival idle-time check         -> DoS / Blackhole Attack
    """

    DOS_IDLE_TICKS = 4   # if a sensor goes silent this many ticks -> DoS alert

    def __init__(self, log_callback):
        self.seen_timestamps = {}   # sensor_id -> set of timestamps already seen
        self.last_seen_tick = {}    # sensor_id -> tick of last received packet
        self.dos_flagged = set()    # sensor_ids currently under an active DoS alert
        self.log = log_callback
        self.alert_counts = {"MALICIOUS": 0, "SUSPICIOUS": 0}

    def _physio_violation(self, pkt):
        lo, hi = PHYSIO_BOUNDS[pkt.sensor_type]
        return not (lo <= pkt.value <= hi)

    def _is_replay(self, pkt):
        seen = self.seen_timestamps.setdefault(pkt.sensor_id, set())
        if pkt.timestamp in seen:
            return True
        seen.add(pkt.timestamp)
        return False

    def check_dos(self, all_sensor_ids, current_tick):
        """Called once per simulation tick to look for sensors that have
        gone silent (a blackhole/DoS attack in progress)."""
        for sid in all_sensor_ids:
            last = self.last_seen_tick.get(sid, current_tick)
            idle = current_tick - last
            if idle >= self.DOS_IDLE_TICKS and sid not in self.dos_flagged:
                self.dos_flagged.add(sid)
                self.alert_counts["MALICIOUS"] += 1
                self.log("ATTACK", f"Detective Agent: Sensor {sid} idle for "
                                    f"{idle} ticks -> DoS/Blackhole attack suspected!")
            elif idle < self.DOS_IDLE_TICKS and sid in self.dos_flagged:
                self.dos_flagged.discard(sid)
                self.log("INFO", f"Sensor {sid} data flow resumed -- DoS alert cleared.")

    def analyze(self, pkt, locally_suspicious):
        """Main decision point: combines the physiological, replay, and
        statistical-outlier checks into one final verdict for this packet."""
        self.last_seen_tick[pkt.sensor_id] = pkt.timestamp
        self.dos_flagged.discard(pkt.sensor_id)

        reasons = []
        status = Status.BENIGN
        is_duplicate_timestamp = self._is_replay(pkt)
        is_physio_violation = pkt.forged or self._physio_violation(pkt)

        if is_physio_violation:
            status = Status.MALICIOUS
            bound = PHYSIO_BOUNDS[pkt.sensor_type]
            reasons.append(f"value {pkt.value} outside physiological bound {bound}")
        elif pkt.replayed or is_duplicate_timestamp:
            status = Status.MALICIOUS
            reasons.append("duplicate timestamp (replay signature)")
        elif locally_suspicious:
            status = Status.SUSPICIOUS
            reasons.append("statistical outlier vs. rolling baseline (CH z-score)")

        pkt.status = status
        if status is Status.MALICIOUS:
            self.alert_counts["MALICIOUS"] += 1
            self.log("ALERT", f"Detective Agent: MALICIOUS on {pkt.sensor_id} "
                               f"({pkt.sensor_type}={pkt.value}{SENSOR_UNITS[pkt.sensor_type]}) "
                               f"- {', '.join(reasons)}")
        elif status is Status.SUSPICIOUS:
            self.alert_counts["SUSPICIOUS"] += 1
            self.log("ALERT", f"Detective Agent: SUSPICIOUS on {pkt.sensor_id} "
                               f"({pkt.sensor_type}={pkt.value}{SENSOR_UNITS[pkt.sensor_type]}) "
                               f"- {', '.join(reasons)} -> intervention request sent to CH")
        return pkt


class BaseStation:
    """Top of the hierarchy -- just tallies the final outcomes."""

    def __init__(self):
        self.total_packets = 0
        self.malicious = 0
        self.suspicious = 0
        self.benign = 0

    def receive(self, pkt):
        self.total_packets += 1
        if pkt.status is Status.MALICIOUS:
            self.malicious += 1
        elif pkt.status is Status.SUSPICIOUS:
            self.suspicious += 1
        else:
            self.benign += 1
