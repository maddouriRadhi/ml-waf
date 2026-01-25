from logger_module import WAFLogger

# Test the logger
logger = WAFLogger()
logs = logger.get_recent_logs(5)
print(f'Found {len(logs)} logs')

for i, log in enumerate(logs[:3]):
    print(f'  {i+1}. {log["timestamp"]} - {log["method"]} {log["url"]} - {log["decision"]}')
