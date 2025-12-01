import json

file_path = r"C:\Users\intel\Desktop\PayloadFactoryUX\dataset\processed_filtered_owasp_strict_balanced\train.balanced.jsonl"

from collections import Counter

with open(file_path, 'r', encoding='utf-8') as f:
    severities = []
    targets = []
    for i in range(1000):
        line = f.readline()
        if not line: break
        data = json.loads(line)
        severities.append(str(data.get('severity_class')))
        targets.append(str(data.get('target')))

    print("Severity Distribution:", Counter(severities))
    print("Target Distribution:", Counter(targets))
