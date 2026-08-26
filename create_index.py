#!/usr/bin/env python3
"""Create the GSI index greenboard + the collector use to list agents / seed
rings. Idempotent (IF NOT EXISTS). Run once after the `slaves` bucket exists."""
from datetime import timedelta
from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions, ClusterTimeoutOptions
from couchbase.auth import PasswordAuthenticator
import config as C

_to = ClusterTimeoutOptions(connect_timeout=timedelta(seconds=20), query_timeout=timedelta(seconds=60))
cl = Cluster("couchbase://%s" % C.CB_HOST,
             ClusterOptions(PasswordAuthenticator(C.CB_USER, C.CB_PASS), timeout_options=_to))
cl.wait_until_ready(timedelta(seconds=25))

DDL = [
    "CREATE INDEX idx_slaves_type ON `%s`(`type`, `master`, `name`)" % C.CB_BUCKET,
    "CREATE INDEX idx_slaves_agent ON `%s`(`master`, `health`) WHERE `type`='agent'" % C.CB_BUCKET,
]
for stmt in DDL:
    try:
        cl.query(stmt.replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS")).execute()
        print("ok:", stmt)
    except Exception as e:
        print("skip:", stmt, "->", e)
print("done")
