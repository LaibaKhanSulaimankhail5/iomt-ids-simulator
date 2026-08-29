import math
import tkinter as tk
from tkinter import ttk, scrolledtext

from models import PATIENT_PROFILES, SENSOR_UNITS, SENSOR_TYPES, Status
from sensors import Sensor
from attacker import Attacker
from detection import ClusterHead, DetectiveAgent, BaseStation

CANVAS_W, CANVAS_H = 760, 560
COLOR = {
    "BENIGN": "#2ecc71", "SUSPICIOUS": "#f39c12", "MALICIOUS": "#e74c3c",
    "attacker": "#c0392b", "ch": "#2980b9", "base": "#8e44ad", "patient": "#16a085",
}


class IoMT_IDS_App:
    def __init__(self, root):
        self.root = root
        self.root.title("IoMT Intrusion Detection System - Rule-Based Simulation")
        self.root.geometry("1180x680")

        self.running = False
        self.tick = 0
        self.speed_ms = tk.IntVar(value=700)
        self.profile_name = tk.StringVar(value="Normal")

        self.cluster_head = ClusterHead()
        self.base_station = BaseStation()
        self.attacker = Attacker()
        self.detective = DetectiveAgent(self.log)

        self._build_topology()
        self._build_ui()
        self._draw_static_topology()

    # -- topology (fixed positions on canvas) ---------------------------
    def _build_topology(self):
        patient_pos = (170, 280)
        ch_pos = (430, 280)
        base_pos = (680, 280)
        attacker_pos = (300, 470)

        self.patient_pos = patient_pos
        self.ch_pos = ch_pos
        self.base_pos = base_pos
        self.attacker_pos = attacker_pos

        self.sensors = []
        radius = 110
        for i, stype in enumerate(SENSOR_TYPES):
            angle = math.radians(90 + i * (360 / len(SENSOR_TYPES)))
            x = patient_pos[0] + radius * math.cos(angle)
            y = patient_pos[1] + radius * math.sin(angle)
            sid = f"{stype}-{i+1}"
            self.sensors.append(Sensor(sid, stype, "Patient-001", (x, y)))

    # -- UI layout --------------------------------------------------------
    def _build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)
        self.canvas = tk.Canvas(left, width=CANVAS_W, height=CANVAS_H, bg="#0f1620", highlightthickness=0)
        self.canvas.pack(padx=8, pady=8)

        right = ttk.Frame(main, width=380)
        right.pack(side="right", fill="y")

        # ---- controls ----
        ctrl = ttk.LabelFrame(right, text="Simulation Control")
        ctrl.pack(fill="x", padx=8, pady=6)
        ttk.Button(ctrl, text="Start", command=self.start).grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(ctrl, text="Stop", command=self.stop).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(ctrl, text="Reset", command=self.reset).grid(row=0, column=2, padx=4, pady=4, sticky="ew")

        ttk.Label(ctrl, text="Speed (ms/tick):").grid(row=1, column=0, sticky="w", padx=4)
        ttk.Scale(ctrl, from_=150, to=1500, variable=self.speed_ms, orient="horizontal").grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=4)

        ttk.Label(ctrl, text="Patient state:").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.OptionMenu(ctrl, self.profile_name, "Normal", *PATIENT_PROFILES.keys()).grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=4)
        for c in range(3):
            ctrl.columnconfigure(c, weight=1)

        # ---- attack panel ----
        atk = ttk.LabelFrame(right, text="Attacker Module")
        atk.pack(fill="x", padx=8, pady=6)
        ttk.Label(atk, text="Target sensor:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.target_var = tk.StringVar(value=self.sensors[0].id)
        ttk.OptionMenu(atk, self.target_var, self.sensors[0].id, *[s.id for s in self.sensors]).grid(
            row=0, column=1, sticky="ew", padx=4)
        ttk.Button(atk, text="Injection Attack", command=lambda: self.launch_attack("injection")).grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=4, pady=3)
        ttk.Button(atk, text="Replay Attack", command=lambda: self.launch_attack("replay")).grid(
            row=2, column=0, columnspan=2, sticky="ew", padx=4, pady=3)
        ttk.Button(atk, text="Blackhole / DoS Attack", command=lambda: self.launch_attack("blackhole")).grid(
            row=3, column=0, columnspan=2, sticky="ew", padx=4, pady=3)
        for c in range(2):
            atk.columnconfigure(c, weight=1)

        # ---- dashboard ----
        dash = ttk.LabelFrame(right, text="Dashboard")
        dash.pack(fill="x", padx=8, pady=6)
        self.dash_labels = {}
        for i, s in enumerate(self.sensors):
            ttk.Label(dash, text=f"{s.id}:").grid(row=i, column=0, sticky="w", padx=4)
            lbl = ttk.Label(dash, text="-- --", width=22)
            lbl.grid(row=i, column=1, sticky="w")
            self.dash_labels[s.id] = lbl
        self.counter_label = ttk.Label(dash, text="Packets: 0 | Benign: 0 | Suspicious: 0 | Malicious: 0",
                                        font=("TkDefaultFont", 9, "bold"))
        self.counter_label.grid(row=len(self.sensors), column=0, columnspan=2, sticky="w", pady=(6, 2), padx=4)

        # ---- log console ----
        logf = ttk.LabelFrame(right, text="Detective Agent - Live Log")
        logf.pack(fill="both", expand=True, padx=8, pady=6)
        self.console = scrolledtext.ScrolledText(logf, height=16, bg="#111418", fg="#d0d0d0",
                                                   insertbackground="white", font=("Consolas", 9))
        self.console.pack(fill="both", expand=True, padx=4, pady=4)
        self.console.tag_config("INFO", foreground="#7fbfff")
        self.console.tag_config("ALERT", foreground="#ff5c5c")
        self.console.tag_config("ATTACK", foreground="#ff9900")

    # -- static topology drawing ------------------------------------------
    def _draw_static_topology(self):
        c = self.canvas
        c.create_line(*self.ch_pos, *self.base_pos, fill="#3a4a5c", width=2, dash=(4, 2))
        c.create_oval(self.patient_pos[0]-30, self.patient_pos[1]-30,
                      self.patient_pos[0]+30, self.patient_pos[1]+30,
                      fill=COLOR["patient"], outline="")
        c.create_text(*self.patient_pos, text="Patient", fill="white", font=("TkDefaultFont", 9, "bold"))

        c.create_rectangle(self.ch_pos[0]-35, self.ch_pos[1]-25, self.ch_pos[0]+35, self.ch_pos[1]+25,
                           fill=COLOR["ch"], outline="")
        c.create_text(*self.ch_pos, text="Cluster\nHead", fill="white", font=("TkDefaultFont", 8, "bold"))

        c.create_rectangle(self.base_pos[0]-40, self.base_pos[1]-25, self.base_pos[0]+40, self.base_pos[1]+25,
                           fill=COLOR["base"], outline="")
        c.create_text(*self.base_pos, text="Base\nStation", fill="white", font=("TkDefaultFont", 8, "bold"))

        self.attacker_icon = c.create_polygon(
            self.attacker_pos[0], self.attacker_pos[1]-20,
            self.attacker_pos[0]-18, self.attacker_pos[1]+15,
            self.attacker_pos[0]+18, self.attacker_pos[1]+15,
            fill="#4a1414", outline=COLOR["attacker"], width=2)
        c.create_text(self.attacker_pos[0], self.attacker_pos[1]+30, text="Attacker",
                      fill="#e74c3c", font=("TkDefaultFont", 8, "bold"))

        self.sensor_nodes = {}
        for s in self.sensors:
            x, y = s.pos
            c.create_line(x, y, *self.ch_pos, fill="#22303d", width=1)
            node = c.create_oval(x-18, y-18, x+18, y+18, fill=COLOR["BENIGN"], outline="white", width=1)
            c.create_text(x, y-26, text=s.type, fill="#cfd8dc", font=("TkDefaultFont", 8, "bold"))
            self.sensor_nodes[s.id] = node

    # -- logging ------------------------------------------------------------
    def log(self, tag, message):
        self.console.insert("end", f"[{tag}] {message}\n", tag)
        self.console.see("end")

    # -- attack launching -----------------------------------------------
    def launch_attack(self, mode):
        target = self.target_var.get()
        self.attacker.launch(mode, target, duration_ticks=6)
        self.log("ATTACK", f"{mode.upper()} attack launched against {target} "
                            f"(active for 6 ticks)")

    # -- simulation control -----------------------------------------------
    def start(self):
        if not self.running:
            self.running = True
            self.log("INFO", "Simulation started.")
            self._loop()

    def stop(self):
        self.running = False
        self.log("INFO", "Simulation stopped.")

    def reset(self):
        self.running = False
        self.tick = 0
        self.cluster_head = ClusterHead()
        self.base_station = BaseStation()
        self.attacker.stop()
        self.detective = DetectiveAgent(self.log)
        self.console.delete("1.0", "end")
        for s in self.sensors:
            self.canvas.itemconfig(self.sensor_nodes[s.id], fill=COLOR["BENIGN"])
            self.dash_labels[s.id].config(text="-- --")
        self.counter_label.config(text="Packets: 0 | Benign: 0 | Suspicious: 0 | Malicious: 0")
        self.log("INFO", "Simulation reset.")

    # -- main tick loop -----------------------------------------------------
    def _loop(self):
        if not self.running:
            return
        self.tick += 1
        for sensor in self.sensors:
            legit_pkt = sensor.generate_packet(self.tick, self.profile_name.get())
            delivered_packets = self.attacker.process(sensor, legit_pkt)

            if self.attacker.active and self.attacker.target_sensor_id == sensor.id:
                self._flash_attacker_link(sensor)

            for pkt in delivered_packets:
                locally_suspicious = self.cluster_head.local_check(pkt)
                pkt = self.detective.analyze(pkt, locally_suspicious)
                self.base_station.receive(pkt)
                self._animate_packet(sensor.pos, self.ch_pos, COLOR[pkt.status.value])
                self._update_sensor_visual(sensor.id, pkt)

        self.detective.check_dos([s.id for s in self.sensors], self.tick)
        self._update_counters()
        self.root.after(int(self.speed_ms.get()), self._loop)

    # -- visuals -------------------------------------------------------------
    def _update_sensor_visual(self, sensor_id, pkt):
        self.canvas.itemconfig(self.sensor_nodes[sensor_id], fill=COLOR[pkt.status.value])
        tag = "" if pkt.status is Status.BENIGN else f"  ! {pkt.status.value}"
        self.dash_labels[sensor_id].config(
            text=f"{pkt.value}{SENSOR_UNITS[pkt.sensor_type]}{tag}")

    def _update_counters(self):
        bs = self.base_station
        self.counter_label.config(
            text=f"Packets: {bs.total_packets} | Benign: {bs.benign} | "
                 f"Suspicious: {bs.suspicious} | Malicious: {bs.malicious}")

    def _flash_attacker_link(self, sensor):
        line = self.canvas.create_line(*self.attacker_pos, *sensor.pos, fill=COLOR["attacker"],
                                        width=2, dash=(3, 2))
        self.canvas.itemconfig(self.attacker_icon, outline="#ff3333")
        self.root.after(int(self.speed_ms.get()) - 50, lambda: self.canvas.delete(line))
        self.root.after(int(self.speed_ms.get()) - 50,
                        lambda: self.canvas.itemconfig(self.attacker_icon, outline=COLOR["attacker"]))

    def _animate_packet(self, start, end, color, steps=8):
        dot = self.canvas.create_oval(start[0]-5, start[1]-5, start[0]+5, start[1]+5, fill=color, outline="")
        dx = (end[0]-start[0]) / steps
        dy = (end[1]-start[1]) / steps

        def step(n=0):
            if n >= steps:
                self.canvas.delete(dot)
                return
            self.canvas.move(dot, dx, dy)
            self.root.after(max(15, int(self.speed_ms.get()) // steps), lambda: step(n+1))
        step()
