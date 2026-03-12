"""
Initialize the plant state database.

Creates the SQLite DB and populates it with default tag values.
Run this before starting the simulation.
"""

import sqlite3
import os

from utils import STATE, INIT_TAGS

DB_PATH = STATE['path']
TABLE = STATE['name']


def init_db():

    # Remove stale DB
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    c = conn.cursor()

    # MiniCPS state table schema: (name TEXT, pid INT, val TEXT)
    c.execute('''
        CREATE TABLE IF NOT EXISTS {} (
            name TEXT NOT NULL,
            pid  INTEGER NOT NULL,
            val  TEXT,
            PRIMARY KEY (name, pid)
        )
    '''.format(TABLE))

    # Insert initial values
    for (tag_name, pid), value in INIT_TAGS.items():
        c.execute(
            "INSERT INTO {} VALUES (?, ?, ?)".format(TABLE),
            (tag_name, pid, value)
        )

    conn.commit()
    conn.close()

    print("[INIT] State DB created at", DB_PATH)
    for (tag_name, pid), value in INIT_TAGS.items():
        print("  {}(pid={}) = {}".format(tag_name, pid, value))


if __name__ == '__main__':
    init_db()
