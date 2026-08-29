from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass
class DataPacket:
    """One reading sent from a sensor toward the cluster head.
    Matches the paper's [Timestamp, Sensor_ID, Patient_ID, Value, Status]."""
    timestamp: int
    sensor_id: str
    patient_id: str
    sensor_type: str
    value: float
    status: Status = Status.BENIGN
    forged: bool = False      # True if the attacker fabricated this packet
    replayed: bool = False    # True if this is a re-sent old packet


# (mean, standard-deviation) per patient health state, per sensor type
PATIENT_PROFILES = {
    "Normal":        {"ECG": (75, 4),   "TEMP": (98.4, 0.15), "SPO2": (98, 0.5), "RESP": (16, 1)},
    "Mild Distress": {"ECG": (95, 6),   "TEMP": (99.6, 0.30), "SPO2": (94, 1.2), "RESP": (22, 2)},
    "Critical":      {"ECG": (130, 10), "TEMP": (101.5, 0.5), "SPO2": (88, 2.0), "RESP": (30, 3)},
}

# Hard physiological limits -- a live human being can NEVER have a value
# outside these, so any reading outside them is an instant red flag.
PHYSIO_BOUNDS = {
    "ECG":  (25, 220),
    "TEMP": (85, 108),
    "SPO2": (50, 100),
    "RESP": (4, 45),
}

SENSOR_UNITS = {"ECG": "bpm", "TEMP": "F", "SPO2": "%", "RESP": "brpm"}
SENSOR_TYPES = ["ECG", "TEMP", "SPO2", "RESP"]
