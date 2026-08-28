# IoMT Intrusion Detection Simulator

This is a simplified implementation based on the paper "An Intrusion
Detection System for Internet of Medical Things" (Thamilarasu et al.,
IEEE Access 2020).

As instructed, we are not training the paper's machine learning models
(SVM, Decision Tree, Naive Bayes, KNN, Random Forest) or its polynomial
regression model. Instead, we built a simulator that generates patient
and network data, injects the attack types described in the paper, and
detects them using rule-based / statistical logic instead of ML.

## Team

- **Hira** -- Data generation (`data_generator.py`)
- **Isha** -- Attack injection (`attack_injector.py`)
- **Laiba** -- Detection logic and dashboard (`detector.py`, `dashboard.py`)

## Project structure

```
config.py            Shared constants used by every module
data_generator.py    Generates normal (attack-free) patient and network data
attack_injector.py   Injects attacks and labels the data
detector.py           Rule-based detection engine and accuracy report
dashboard.py           Streamlit dashboard for visualizing results
main.py               Runs the full pipeline end-to-end
requirements.txt
```

## Setup

```bash
pip install -r requirements.txt
```

## Running the project

Run everything at once:
```bash
python main.py
```
This generates `normal_data.csv`, `labeled_data.csv`, and
`detection_results.csv`, and prints an accuracy summary in the terminal.

Then view the dashboard:
```bash
streamlit run dashboard.py
```

Each module can also be run and tested on its own:
```bash
python data_generator.py     # produces normal_data.csv
python attack_injector.py    # produces labeled_data.csv (needs normal_data.csv)
python detector.py           # produces detection_results.csv (needs labeled_data.csv)
```

Note: `config.py` sets a fixed random seed, so running `data_generator.py`
on any machine produces identical output. This means each person can
generate the earlier stage's file on their own machine instead of
waiting on someone else to send it.

## What each part does

**Data generation (Hira)**
Simulates a WBAN cluster of 5 sensors and 1 cluster head. Produces heart
rate readings (sensors only) and network traffic features (packet rate,
packet size) for every device, once per second, over a 10-minute window.
All values are normal/attack-free.

**Attack injection (Isha)**
Injects five attack types from the paper's attack model (Table 3), each
on a specific device during a specific time window:
- DoS -- Sender Radio Exhaustion (the sensor floods its own traffic)
- DoS -- Receiver Radio Exhaustion (decoy packets flood the cluster head)
- Sink Hole (traffic gets redirected, so packet rate collapses)
- Data Fabrication (a physiologically impossible heart-rate value)
- Data Falsification (a slow, subtle drift in a real reading, harder to
  detect, labeled "suspicious" rather than "malicious")

Every row is labeled with the ground truth (`normal` / `suspicious` /
`malicious`) and an `attack_type`.

**Detection and dashboard (Laiba)**
Two independent rule-based checks, no ML training involved:
1. A rolling, outlier-resistant (median/MAD-based) z-score on packet
   rate, which catches both DoS floods and sinkhole drops.
2. Physiological bounds plus a rolling z-score on heart rate, which
   catches both fabrication and falsification.

The two checks are combined into one final verdict per row and compared
against the ground truth to produce an accuracy summary. `dashboard.py`
shows this visually in the browser.

## Notes on tuning

If the attack durations or intensities in `attack_injector.py` are
changed, the detection thresholds in `detector.py`
(`ROLLING_WINDOW_SEC`, `Z_THRESHOLD_MALICIOUS`, `Z_THRESHOLD_SUSPICIOUS`)
may need to be adjusted to keep accuracy reasonable.
