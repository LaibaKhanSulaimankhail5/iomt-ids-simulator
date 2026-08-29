import math
import random
from models import PATIENT_PROFILES, DataPacket


class DataGenerator:
    """Produces a continuous, slightly-noisy physiological time series
    (a slow sine-wave cycle + a bounded random walk + gaussian noise)
    so the stream looks like real vitals instead of pure random numbers."""

    def __init__(self, sensor_type):
        self.sensor_type = sensor_type
        self.phase = random.uniform(0, 6.28)
        self.walk = 0.0

    def next_value(self, profile_name):
        mean, sd = PATIENT_PROFILES[profile_name][self.sensor_type]
        self.phase += 0.35
        wave = math.sin(self.phase) * (sd * 0.6)
        self.walk += random.uniform(-sd * 0.05, sd * 0.05)
        self.walk = max(-sd, min(sd, self.walk))
        noise = random.gauss(0, sd * 0.25)
        return round(mean + wave + self.walk + noise, 1)


class Sensor:
    """A single wireless body sensor attached to the patient
    (a Category-A WBAN device, in the paper's terms)."""

    def __init__(self, sensor_id, sensor_type, patient_id, pos):
        self.id = sensor_id
        self.type = sensor_type
        self.patient_id = patient_id
        self.pos = pos  # (x, y) position on the GUI canvas
        self.generator = DataGenerator(sensor_type)
        self.last_sent_packet = None

    def generate_packet(self, tick, profile_name):
        """Produces one fresh reading as a DataPacket, ready to be sent
        toward the cluster head (before the attacker gets a chance to
        interfere with it)."""
        value = self.generator.next_value(profile_name)
        pkt = DataPacket(
            timestamp=tick, sensor_id=self.id, patient_id=self.patient_id,
            sensor_type=self.type, value=value,
        )
        self.last_sent_packet = pkt
        return pkt
