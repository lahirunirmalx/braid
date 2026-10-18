#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 lahiru
# Requires: pyserial (PlatformIO's python has it: ~/.platformio/penv/bin/python)
# Run:      python3 tools/range_log.py [--port /dev/ttyUSB0] [--out range-logs]
#           (from firmware/examples/demo-3board; logs land in ./range-logs, git-ignored)
"""Range-test logger for the Braid demo probe (board C).

Reads C's serial console and writes, with a host timestamp on every line:
  <out>/range-YYYYmmdd-HHMMSS.csv      one row per event (see COLUMNS)
  <out>/range-YYYYmmdd-HHMMSS.raw.log  every serial line, timestamped

Events: PRESS / RELEASE (BRRX value 1 / 0, with hops, seq, rssi), STATE,
BOUND, CLOSED, LINK, STAT (every 5 s: session state, rx count), EVT, RESET,
and MARK: type a note (e.g. "30m gate") and press Enter to stamp where you
are. Ctrl+C stops and prints a summary.

Opening the port resets a CH340 devkit; C restarts with its stored
configuration and re-binds when A is in range (logged as RESET, STATE).
"""

import argparse
import csv
import glob
import os
import re
import sys
import threading
import time
from datetime import datetime

import serial

COLUMNS = ["host_time", "elapsed_s", "event", "src", "hops", "seq", "value", "rssi", "note"]

RE_RX = re.compile(r"BRRX src=0x([0-9A-Fa-f]{4}) hops=(\d+) seq=(\d+) value=(\d+)(?: rssi=(-?\d+))?")
RE_STATE = re.compile(r"BRSTATE probe rec=\d+ (\S+) -> (\S+)")
RE_BOUND = re.compile(r"BRBOUND s=\S+ peer=0x([0-9A-Fa-f]{4})")
RE_CLOSED = re.compile(r"BRCLOSED (.*)")
RE_LINK = re.compile(r"BRLINK neighbour 0x([0-9A-Fa-f]{4}).*?rssi=(-?\d+)")
RE_STAT = re.compile(r"BRSTAT .*?sess=(\S+).*? delivered=(\d+).*? rx=(\d+)")
RE_EVT = re.compile(r"(BREVT .*)")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def pick_port(arg):
    if arg:
        return arg
    ports = sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
    if not ports:
        sys.exit("no /dev/ttyUSB* or /dev/ttyACM* found: plug in board C or pass --port")
    return ports[0]


class Logger:
    def __init__(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        stem = os.path.join(out_dir, "range-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        self.csv_path = stem + ".csv"
        self.raw_path = stem + ".raw.log"
        self.csv_f = open(self.csv_path, "w", newline="", encoding="ascii", errors="replace")
        self.raw_f = open(self.raw_path, "w", encoding="ascii", errors="replace")
        self.w = csv.writer(self.csv_f)
        self.w.writerow(COLUMNS)
        self.t0 = time.monotonic()
        self.lock = threading.Lock()
        self.presses = 0
        self.last_press = None      # (host_time, rssi, hops)
        self.min_rssi = None
        self.state = "?"

    def row(self, event, src="", hops="", seq="", value="", rssi="", note=""):
        with self.lock:
            t = now_str()
            self.w.writerow([t, "%.3f" % (time.monotonic() - self.t0), event, src, hops, seq, value, rssi, note])
            self.csv_f.flush()
            return t

    def raw(self, line):
        with self.lock:
            self.raw_f.write("%s %s\n" % (now_str(), line))
            self.raw_f.flush()

    def feed(self, line):
        self.raw(line)
        m = RE_RX.search(line)
        if m:
            src, hops, seq, value, rssi = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5) or ""
            ev = "PRESS" if value == "1" else "RELEASE"
            t = self.row(ev, "0x" + src.upper(), hops, seq, value, rssi)
            if ev == "PRESS":
                self.presses += 1
                self.last_press = (t, rssi, hops)
                if rssi:
                    r = int(rssi)
                    self.min_rssi = r if self.min_rssi is None else min(self.min_rssi, r)
                print("%s  PRESS #%d  from 0x%s  hops=%s  rssi=%s" % (t[11:], self.presses, src.upper(), hops,
                                                                     rssi or "?"), flush=True)
            return
        m = RE_STATE.search(line)
        if m:
            self.state = m.group(2)
            t = self.row("STATE", note="%s -> %s" % (m.group(1), m.group(2)))
            print("%s  state %s -> %s" % (t[11:], m.group(1), m.group(2)), flush=True)
            return
        m = RE_BOUND.search(line)
        if m:
            self.row("BOUND", src="0x" + m.group(1).upper())
            return
        m = RE_CLOSED.search(line)
        if m:
            t = self.row("CLOSED", note=m.group(1))
            print("%s  session CLOSED (%s)" % (t[11:], m.group(1)), flush=True)
            return
        m = RE_LINK.search(line)
        if m:
            self.row("LINK", src="0x" + m.group(1).upper(), rssi=m.group(2))
            return
        m = RE_STAT.search(line)
        if m:
            self.row("STAT", note="sess=%s delivered=%s rx=%s" % (m.group(1), m.group(2), m.group(3)))
            return
        m = RE_EVT.search(line)
        if m:
            self.row("EVT", note=m.group(1))
            return
        if line.startswith("rst:"):
            t = self.row("RESET", note=line)
            print("%s  board reset (%s)" % (t[11:], line), flush=True)

    def mark(self, note):
        t = self.row("MARK", note=note)
        print("%s  MARK %s" % (t[11:], note), flush=True)

    def close(self):
        with self.lock:
            self.csv_f.close()
            self.raw_f.close()

    def summary(self):
        print()
        print("presses received: %d" % self.presses)
        if self.last_press:
            t, rssi, hops = self.last_press
            print("last press:       %s  rssi=%s hops=%s" % (t, rssi or "?", hops))
        if self.min_rssi is not None:
            print("weakest press:    rssi=%d" % self.min_rssi)
        print("csv: %s" % self.csv_path)
        print("raw: %s" % self.raw_path)


def mark_reader(log, stop):
    for line in sys.stdin:
        if stop.is_set():
            return
        note = line.strip()
        log.mark(note if note else "(mark)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", help="serial port of board C (default: first /dev/ttyUSB* / ttyACM*)")
    ap.add_argument("--out", default="range-logs", help="output directory (default: range-logs)")
    ap.add_argument("--baud", type=int, default=115200)
    args = ap.parse_args()

    port = pick_port(args.port)
    log = Logger(args.out)
    stop = threading.Event()
    threading.Thread(target=mark_reader, args=(log, stop), daemon=True).start()
    log.row("START", note="port=%s" % port)
    print("logging %s -> %s" % (port, log.csv_path))
    print("type a note + Enter to MARK your position; Ctrl+C to stop")

    buf = b""
    ser = None
    try:
        while True:
            if ser is None:
                try:
                    ser = serial.Serial()
                    ser.port = port
                    ser.baudrate = args.baud
                    ser.timeout = 0.2
                    ser.dtr = False
                    ser.rts = False
                    ser.open()
                except (serial.SerialException, OSError) as e:
                    ser = None
                    log.row("PORT", note="open failed: %s" % e)
                    time.sleep(1.0)
                    continue
            try:
                data = ser.read(4096)
            except (serial.SerialException, OSError) as e:
                log.row("PORT", note="lost: %s" % e)
                print("%s  serial port lost, retrying" % now_str()[11:], flush=True)
                try:
                    ser.close()
                except Exception:
                    pass
                ser = None
                time.sleep(1.0)
                continue
            if not data:
                continue
            buf += data
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode("ascii", "replace").strip()
                line = re.sub(r"\x1b\[[0-9;]*m", "", line)  # ESP-IDF log colours
                if line:
                    log.feed(line)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        log.row("STOP")
        if ser is not None:
            ser.close()
        log.summary()
        log.close()


if __name__ == "__main__":
    main()
