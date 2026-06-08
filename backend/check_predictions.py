import sqlite3

conn = sqlite3.connect('logs.db')
conn.row_factory = sqlite3.Row
cursor = conn.execute("SELECT raw_log FROM analyzed_logs WHERE id = 9759")
row = cursor.fetchone()
if row:
    print(row['raw_log'])
conn.close()
