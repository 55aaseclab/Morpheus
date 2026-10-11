from collections import Counter
import json
import tempfile

from semantics import identifier


class RuleStore:
    def __init__(self, directory):
        self.stream = tempfile.TemporaryFile(mode="w+b", dir=directory)
        self.index = []
        self.statuses = Counter()
        self.edge_ids = {}
        self.edge_objects = {}

    def edge_id(self, edge):
        identity = id(edge)
        if identity not in self.edge_ids or self.edge_objects[identity] is not edge:
            self.edge_ids[identity] = identifier("edge", json.dumps(edge, sort_keys=True))
            self.edge_objects[identity] = edge
        return self.edge_ids[identity]

    def append(self, rule):
        serialized = {**rule, "path": {**rule["path"], "edges": [self.edge_id(edge)
                                                                for edge in rule["path"]["edges"]]}}
        offset = self.stream.seek(0, 2)
        payload = json.dumps(serialized, separators=(",", ":")).encode() + b"\n"
        self.stream.write(payload)
        self.index.append((rule["id"], offset, len(payload)))
        self.statuses[rule["status"]] += 1

    def extend(self, rules):
        for rule in rules:
            self.append(rule)

    def __len__(self):
        return len(self.index)

    def __iter__(self):
        for payload in self.encoded_records():
            yield json.loads(payload)

    def encoded_records(self):
        self.stream.flush()
        for _, offset, size in sorted(self.index):
            self.stream.seek(offset)
            yield self.stream.read(size).rstrip(b"\n")

    def close(self):
        self.stream.close()
