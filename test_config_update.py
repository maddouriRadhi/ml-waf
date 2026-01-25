import json

# Test configuration update
with open('config.json', 'r') as f:
    config = json.load(f)

print(f"Current ML threshold: {config['ml_classifier']['threshold']}")

# Simulate updating threshold
config['ml_classifier']['threshold'] = 0.75

with open('config.json', 'w') as f:
    json.dump(config, f, indent=4)

print(f"Updated ML threshold to: {config['ml_classifier']['threshold']}")

# Verify update
with open('config.json', 'r') as f:
    updated_config = json.load(f)

print(f"Verified ML threshold: {updated_config['ml_classifier']['threshold']}")
