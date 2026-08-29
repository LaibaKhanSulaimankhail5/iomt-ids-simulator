# IoMT Intrusion Detection Simulator

A live, visual, rule-based simulation based on the paper "An Intrusion
Detection System for Internet of Medical Things" (Thamilarasu et al.,
IEEE Access 2020).

As instructed, no machine learning is trained here. Detection is done
with rule-based / threshold / signature checks only -- mirroring the
paper's Sensor Agent, Cluster-Head Agent, and Detective Agent design.

No pip installs are needed -- everything runs on Python's built-in
`tkinter` library.

## Team

- **Hira** -- Sensors and data generation (`sensors.py`)
- **Isha** -- Attacker module (`attacker.py`)
- **Laiba** -- Detection engine and GUI (`detection.py`, `gui_app.py`)

## Project structure

```
models.py       Shared data models and constants (packet format, patient
                profiles, physiological bounds) -- used by every module
sensors.py      Simulates a patient's body sensors producing vitals
attacker.py     Simulates an attacker tampering with sensor data
detection.py    Rule-based detection engine (Cluster Head + Detective Agent)
gui_app.py      The live Tkinter simulation window
main.py         Entry point -- run this to launch the simulation
```

## Running the project

```bash
python main.py
```

A window opens showing a patient with 4 sensors (ECG, TEMP, SPO2,
RESP), a Cluster Head, a Base Station, and an Attacker. Click **Start**
to begin the simulation, then use the Attacker Module panel to launch
an attack on any sensor and watch it get detected live.

## Terminology (what each part means)

- **ECG / TEMP / SPO2 / RESP** -- standard patient vital signs: heart
  rate, body temperature, blood-oxygen saturation, and breathing rate.
- **Sensor** -- a simulated wearable device producing one vital's
  readings for the patient.
- **Cluster Head** -- collects data from all sensors and runs a fast,
  local statistical check (rolling mean/standard deviation) on each
  reading.
- **Attacker** -- sits between a chosen sensor and the Cluster Head and
  can launch three attack types from the paper's attack model:
  - **Injection** -- fabricates a physiologically impossible reading
    (data fabrication/falsification)
  - **Replay** -- re-transmits an old, captured packet repeatedly
  - **Blackhole** -- silently drops packets (denial-of-service)
- **Detective Agent** -- performs deeper rule-based checks: physiological
  bound violations, duplicate-timestamp (replay) detection, and
  idle-time (DoS) detection. This name and role come directly from the
  paper (Section IV).
- **Base Station** -- the final destination that tallies how many
  readings were benign, suspicious, or malicious. The paper refers to
  this as the hospital server/cloud that the Cluster Head forwards data
  to; "Base Station" is our label for it in the visualization.
- **Benign / Suspicious / Malicious** -- the three possible verdicts a
  reading can get: benign (normal), suspicious (a statistical outlier,
  not confirmed), or malicious (confirmed attack).

## Detection logic (all rule-based, no ML)

1. **Cluster Head check** -- flags a reading as a local outlier if it's
   more than 3 standard deviations from that sensor's own recent
   rolling average.
2. **Detective Agent checks**, in priority order:
   - Physiological bound violation (or a forged packet) -> **malicious**
   - Duplicate timestamp (replay signature) -> **malicious**
   - Local statistical outlier only -> **suspicious**
3. **DoS/blackhole check** -- runs every tick; if a sensor has sent
   nothing for 4+ ticks, it's flagged as a suspected DoS/blackhole attack.

## Notes on tuning

Thresholds live at the top of `detection.py`: `Z_THRESHOLD` (Cluster
Head outlier sensitivity) and `DOS_IDLE_TICKS` (how long a sensor can
go silent before a DoS alert fires). Physiological bounds and patient
health profiles live in `models.py`.
