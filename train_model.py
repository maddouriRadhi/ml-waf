#!/usr/bin/env python3
"""Train a simple Random-Forest WAF model and save to models/waf_model.pkl

Expected CSV columns (case-insensitive):
    url, method, body, label
label must be 0 (benign) or 1 (malicious)

Usage
-----
$ python train_model.py training_data.csv 0.8
First arg  = path to CSV
Second arg = threshold (default 0.8)
"""
import sys, os, pickle, logging
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

if len(sys.argv) < 2:
    sys.exit('Usage: python train_model.py data.csv [threshold]')

csv_path  = sys.argv[1]
threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.8

if not os.path.exists(csv_path):
    sys.exit(f'File {csv_path} not found')

os.makedirs('models', exist_ok=True)

logging.info('Loading dataset …')
df = pd.read_csv(csv_path)

required = {'url', 'method', 'body', 'label'}
if not required.issubset(df.columns.str.lower()):
    sys.exit(f'Dataset must contain columns: {required}')

df.rename(columns=str.lower, inplace=True)
X_raw, y = df[['url', 'method', 'body']], df['label']

extractor = FeatureExtractor()

logging.info('Extracting features …')
features = []
for url, method, body in zip(X_raw['url'], X_raw['method'], X_raw['body']):
    req_line = f"{method} {url} HTTP/1.1\r\n\r\n{body}"
    features.append(extractor.extract(req_line))
X_feat = pd.DataFrame(features)

X_train, X_test, y_train, y_test = train_test_split(X_feat, y, test_size=0.2, random_state=42, stratify=y)

logging.info('Training RandomForest …')
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
pred_prob = clf.predict_proba(X_test)[:,1]

logging.info('\n' + classification_report(y_test, pred))
logging.info(f'ROC-AUC: {roc_auc_score(y_test, pred_prob):.3f}')

model_path = 'models/waf_model.pkl'
with open(model_path, 'wb') as f:
    pickle.dump({'model': clf, 'threshold': threshold}, f)

logging.info(f'✅ Model saved to {model_path} (threshold={threshold})')
