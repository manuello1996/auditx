from __future__ import annotations
from typing import Callable, Dict
from auditx.core.facts import register_provider

try:
    import pymysql  # type: ignore
except Exception:
    pymysql = None

def _mysql_base(params: Dict, progress: Callable[[str], None] | None = None) -> Dict:
    """Collect minimal MySQL facts: version and selected variables (whitelist).
    Expected params: {host, user, password, database, port?}
    """
    if not pymysql:
        return {"mysql.warning": "pymysql not installed; install auditx[mysql]"}
    required = {"host", "user", "password", "database"}
    if not required.issubset(set(params.keys())):
        return {"mysql.error": "Missing MySQL connection params"}
    if progress:
        progress("Connecting to MySQL server")
    conn = pymysql.connect(
        host=params["host"],
        port=int(params.get("port", 3306)),
        user=params["user"],
        password=params["password"],
        database=params["database"],
        connect_timeout=5,
        read_timeout=5,
        write_timeout=5,
        charset="utf8mb4",
        autocommit=True,
    )
    facts: Dict = {}
    try:
        with conn.cursor() as cur:
            if progress:
                progress("Fetching server version")
            cur.execute("SELECT VERSION()")
            row = cur.fetchone()
            facts["mysql.version"] = row[0] if row else "unknown"
            if progress:
                progress("Fetching selected configuration variables")
            cur.execute("SHOW VARIABLES WHERE Variable_name IN ('read_only','slow_query_log','long_query_time')")
            facts["mysql.variables"] = {name: value for name, value in cur.fetchall()}
    finally:
        try:
            conn.close()
        except Exception:
            pass
    if progress:
        progress("Disconnected from MySQL server")
    return facts

register_provider("mysql", _mysql_base)
