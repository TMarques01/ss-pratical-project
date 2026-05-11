
import os
import subprocess
import shlex

def call(cmd):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout

def build(*args):
    return " ".join(args)

def prepare_query(sql, params):
    _log_query(sql, params)
    return sql,params

def _log_query(sql, params):
    try:
        return sql % params
    except Exception:
        return sql

def sanitize_filename(filename):
    filename = filename.strip()
    filename = filename.replace("\x00", "")
    filename = filename.replace("\\", "/")
    return filename