import pandas as pd
import xgboost as xgb
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score
from sklearn.preprocessing import LabelEncoder

normal = pd.read_csv('normal_traffic_dataset.csv')
attack = pd.read_csv('attack_dataset.csv')

normal['label'] = 0
attack['label'] = 1
df = pd.concat([normal, attack], ignore_index=True)

drop_cols = ['flow_id','flow_ip_src','flow_ip_dst','min_time','max_time','forward_packets','receiving_packets','fragments','target']
df.drop(columns=[col for col in drop_cols if col in df.columns], inplace=True)

features = ['flow_srcport','flow_dstport','flow_proto','num_packets','avg_packet_size','tcp_window_size_avg','total_payload','flow_duration']
df = df[features + ['label']].dropna()

le = LabelEncoder()
df['flow_proto'] = le.fit_transform(df['flow_proto'])
df.drop_duplicates(inplace=True)

X, y = df[features], df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

ratio = len(y_train[y_train==0]) / len(y_train[y_train==1])
model = xgb.XGBClassifier(n_estimators=200, learning_rate=0.05, max_depth=5,
                          scale_pos_weight=ratio, subsample=0.8, colsample_bytree=0.8, random_state=42)
model.fit(X_train, y_train)

threshold = 0.15
proba = model.predict_proba(X_test)[:, 1]
y_pred = (proba > threshold).astype(int)

print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")

joblib.dump({'model': model, 'threshold': threshold, 'label_encoder': le}, 'python/training/traffic_model.pkl')