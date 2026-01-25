import sqlite3

# Connect to database
conn = sqlite3.connect('logs/waf.db')
cursor = conn.cursor()

# Check alerts table
cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = cursor.fetchall()
print('Tables:', [t[0] for t in tables])

if 'alerts' in [t[0] for t in tables]:
    # Check alerts table
    cursor.execute('SELECT COUNT(*) FROM alerts')
    count = cursor.fetchone()[0]
    print(f'Alerts in database: {count}')
    
    if count > 0:
        cursor.execute('SELECT timestamp, ip, alert_type, severity, message FROM alerts ORDER BY id DESC LIMIT 3')
        rows = cursor.fetchall()
        print('Recent alerts:')
        for row in rows:
            print(f'  {row}')
    else:
        print('No alerts found in database')
else:
    print('No alerts table found')

conn.close()

# Test WAFLogger alerts
from logger_module import WAFLogger
logger = WAFLogger()
alerts = logger.get_alerts(5)
print(f'WAFLogger found {len(alerts)} alerts')
