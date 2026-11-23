import csv
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd

from src.prediction.model_loader import predict, select
from src.preprocessing.feature_config import CATEGORICAL_FEATURES, FULL, PCAP
from src.traffic.flow_builder import FlowBuilder
from src.traffic.tshark_extractor import extract

LOG = logging.getLogger(__name__)
MAX_ROWS = 100000


def csv_batches(path):
    allowed = set(FULL) | {"id", "label", "attack_cat"}
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        header = next(reader, [])
        if len(set(header)) != len(header) or not set(FULL) <= set(header) <= allowed:
            raise ValueError("CSV requires the 42 UNSW feature columns. Only id, label and attack_cat are optional.")
        buffer = []
        for index, row in enumerate(reader, 1):
            if len(row) != len(header) or index > MAX_ROWS:
                raise ValueError(f"Invalid row width or row limit at CSV record {index}")
            buffer.append(row)
            if len(buffer) == 512:
                yield numeric_frame(buffer, header)
                buffer.clear()
        if buffer:
            yield numeric_frame(buffer, header)


def numeric_frame(rows, header):
    df = pd.DataFrame(rows, columns=header)[FULL].replace("", np.nan)
    for col in set(FULL) - set(CATEGORICAL_FEATURES):
        df[col] = pd.to_numeric(df[col], errors="raise")
        if np.isinf(df[col]).any():
            raise ValueError("Infinite CSV feature value")
    return df


class Jobs:
    def __init__(self, store):
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="analysis")
        self.slots = threading.BoundedSemaphore(4)
        self.cancel_events = {}
        self.lock = threading.Lock()

    def submit(self, cap, name="auto"):
        settings = self.store.settings()
        family = "full" if cap["suffix"] == ".csv" else "pcap"
        chosen = select(family, settings[family + "_model"] if name == "auto" else name)
        if not self.slots.acquire(blocking=False):
            raise ValueError("Analysis queue is full. Wait for a job to finish.")
        try:
            with self.store.connect() as db:
                rid = db.execute("""INSERT INTO runs(capture,family,model,version,schema,idle)
                  VALUES(?,?,?,?,?,?)""", (cap["id"], family, chosen["name"], chosen["version"],
                  json.dumps(chosen["schema"]), settings["idle"])).lastrowid
            event = threading.Event()
            with self.lock:
                self.cancel_events[rid] = event
            self.pool.submit(self.process, rid, cap, chosen, settings, event)
            return rid
        except Exception:
            self.slots.release()
            raise

    def cancel(self, rid):
        with self.lock:
            event = self.cancel_events.get(rid)
            if event:
                event.set()

    def stage(self, rid, stage):
        with self.store.connect() as db:
            db.execute("UPDATE runs SET status='Processing', stage=? WHERE id=?", (stage, rid))

    def process(self, rid, cap, model, settings, event):
        def check():
            if event.is_set():
                raise InterruptedError("Cancelled by analyst")
        try:
            check()
            path = self.store.file(cap)
            self.stage(rid, "Validating feature rows" if model["family"] == "full" else "Extracting frames with TShark")
            is_csv = model["family"] == "full"
            frames = mapped = None
            skipped = {}
            flow_count = 0
            if not is_csv:
                builder = FlowBuilder(settings["idle"])
                frames, skipped = extract(path, builder.add)
                mapped = frames - sum(skipped.values())
            self.stage(rid, "Classifying and storing evidence")
            with self.store.connect() as db:
                if is_csv:
                    for batch in csv_batches(path):
                        check()
                        predictions = predict(batch, model)
                        for row, result in zip(batch.itertuples(), predictions):
                            flow_count += 1
                            stats = {"proto": str(row.proto), "dur": None if pd.isna(row.dur) else row.dur}
                            self.save_flow(db, rid, flow_count, stats, result, settings)
                else:
                    for start in range(0, len(builder.flows), 512):
                        check()
                        group = builder.flows[start:start+512]
                        stats = [f.summary() for f in group]
                        valid = [s for f, s in zip(group, stats) if not f.unsupported()]
                        predictions = iter(predict(pd.DataFrame(valid)[PCAP], model) if valid else [])
                        for f, s in zip(group, stats):
                            flow_count += 1
                            fid = self.save_flow(db, rid, flow_count, s, None if f.unsupported() else next(predictions), settings, f)
                            db.executemany("INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                ((fid,p.frame,p.ns,p.src,p.dst,p.sport,p.dport,p.proto,p.length,int(direction),p.flags)
                                 for p,direction in f.packets))
                check()
                db.execute("""UPDATE runs SET status='Completed',stage='Ready',frames=?,mapped=?,nflows=?,skipped=?
                              WHERE id=?""", (frames, mapped, flow_count, json.dumps(skipped), rid))
        except Exception as exc:
            if not isinstance(exc, (ValueError, InterruptedError, UnicodeError, csv.Error)):
                LOG.exception("Analysis %s failed", rid)
            message = str(exc)[:350] if isinstance(exc, (ValueError, InterruptedError, UnicodeError, csv.Error)) else "Processing failed. See the local server log."
            with self.store.connect() as db:
                db.execute("UPDATE runs SET status=?,stage='Stopped',message=? WHERE id=?",
                           ("Cancelled" if isinstance(exc, InterruptedError) else "Failed", message, rid))
        finally:
            with self.lock:
                self.cancel_events.pop(rid, None)
            self.slots.release()

    @staticmethod
    def save_flow(db, rid, number, stats, prediction, settings, flow=None):
        cat, score = prediction or (None, None)
        severity = settings["severity"].get(cat, "Low") if cat else None
        endpoints = (flow.first, flow.last, flow.src, flow.dst, flow.sport, flow.dport) if flow else (None,)*6
        fid = db.execute("""INSERT INTO flows(run,row_no,first_ns,last_ns,src,dst,sport,dport,proto,dur,
                        packets,bytes,category,score,severity,reason,stats) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (rid, number, *endpoints, stats["proto"], stats["dur"], stats.get("packets"),
                         stats.get("bytes"), cat, score, severity, flow.unsupported() if flow else None,
                         json.dumps(stats))).lastrowid
        if settings["alerts"] and cat and cat != "Normal":
            db.execute("INSERT INTO alerts(flow) VALUES(?)", (fid,))
        return fid
