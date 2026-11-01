python -c "
import json
with open('checkpoints/full_blocked_2stage/lodo_results.json') as f:
    r = json.load(f)
print('Blocked CV results:')
for fold, m in r.items():
    print(f'  {fold}: {m.get(\"attack_roc_auc\", \"N/A\")}')
"