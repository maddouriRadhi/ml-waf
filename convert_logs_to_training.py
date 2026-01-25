#!/usr/bin/env python3
"""Convert waf_logs.csv into a labelled training set for train_model.py

Label rule:
  decision starts with "BLOCKED"  -> label = 1 (malicious)
  otherwise                        -> label = 0 (benign)
Adds an empty body column for GET rows.
Output: training_data.csv next to the input file.
Usage:
  python convert_logs_to_training.py logs/waf_logs.csv
"""
import sys, pandas as pd, os

if len(sys.argv) < 2:
    sys.exit('Usage: python convert_logs_to_training.py path/to/waf_logs.csv')

src = sys.argv[1]
if not os.path.exists(src):
    sys.exit(f'{src} not found')

print('Reading', src)
df = pd.read_csv(src)

required = {'url', 'method', 'decision'}
if not required.issubset(df.columns):
    sys.exit(f'Input must contain columns {required}')

df['body']   = ''
df['label']  = df['decision'].str.startswith('BLOCKED').astype(int)

out = os.path.join(os.path.dirname(src), 'training_data.csv')
df[['url','method','body','label']].to_csv(out, index=False)
print('✅ training data saved to', out)
