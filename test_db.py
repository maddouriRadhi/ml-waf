import sqlite3

# Connect to database
conn = sqlite3.connect('logs/waf.db')
cursor = conn.cursor()

# Check tables
cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = cursor.fetchall()
print('Tables:', tables)

if tables:
    # Check requests table
    cursor.execute('SELECT COUNT(*) FROM requests')
    count = cursor.fetchone()[0]
    print(f'Requests in database: {count}')
    
    if count > 0:
        cursor.execute('SELECT timestamp, method, url, decision FROM requests ORDER BY id DESC LIMIT 3')
        rows = cursor.fetchall()
        print('Recent logs:')
        for row in rows:
            print(f'  {row}')
    else:
        print('No requests found in database')
else:
    print('No tables found')

conn.close()
