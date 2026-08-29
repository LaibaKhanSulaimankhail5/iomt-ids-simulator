import random
from models import PHYSIO_BOUNDS, DataPacket


class Attacker:
    """
    Three attack modes:
        injection  -> Data Fabrication (paper: impossible/extreme values)
        replay     -> re-transmits a captured legitimate packet repeatedly
        blackhole  -> Denial-of-Service by silently dropping packets
    """

    def __init__(self):
        self.mode = None                # None | 'injection' | 'replay' | 'blackhole'
        self.target_sensor_id = None
        self.ticks_remaining = 0
        self._captured_packet = None

    @property
    def active(self):
        return self.mode is not None and self.ticks_remaining > 0

    def launch(self, mode, sensor_id, duration_ticks=6):
        """Called when the user clicks an attack button in the GUI."""
        self.mode = mode
        self.target_sensor_id = sensor_id
        self.ticks_remaining = duration_ticks
        self._captured_packet = None

    def stop(self):
        self.mode = None
        self.target_sensor_id = None
        self.ticks_remaining = 0

    def process(self, sensor, legit_packet):
        """Given the legitimate packet a sensor just produced, decides
        what actually reaches the cluster head. Returns a LIST of packets
        to deliver (can be empty, one, or more than one)."""
        if not self.active or sensor.id != self.target_sensor_id:
            return [legit_packet]

        delivered = []
        if self.mode == "blackhole":
            # DoS: the packet is silently dropped, nothing gets through
            delivered = []
        elif self.mode == "injection":
            # Data fabrication: the real packet still gets through, but a
            # forged, physiologically-impossible packet rides along with it
            lo, hi = PHYSIO_BOUNDS[sensor.type]
            forged_value = round(random.choice([hi + random.uniform(10, 40),
                                                  lo - random.uniform(10, 40)]), 1)
            forged = DataPacket(
                timestamp=legit_packet.timestamp, sensor_id=sensor.id,
                patient_id=sensor.patient_id, sensor_type=sensor.type,
                value=forged_value, forged=True,
            )
            delivered = [legit_packet, forged]
        elif self.mode == "replay":
            # First packet is captured, then the SAME old packet keeps
            # getting re-sent -- its timestamp never changes, which is
            # exactly how the detector will catch it
            if self._captured_packet is None:
                self._captured_packet = legit_packet
                delivered = [legit_packet]
            else:
                replay_copy = DataPacket(
                    timestamp=self._captured_packet.timestamp,
                    sensor_id=self._captured_packet.sensor_id,
                    patient_id=self._captured_packet.patient_id,
                    sensor_type=self._captured_packet.sensor_type,
                    value=self._captured_packet.value,
                    replayed=True,
                )
                delivered = [replay_copy]
        else:
            delivered = [legit_packet]

        self.ticks_remaining -= 1
        if self.ticks_remaining <= 0:
            self.stop()
        return delivered
