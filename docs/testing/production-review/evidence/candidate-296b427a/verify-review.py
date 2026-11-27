"""Recompute both review scores and verify the cited source-bound test receipts."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = 'sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    scorer = [sys.executable, str(ROOT / 'scripts/production_score.py')]
    source = subprocess.check_output([*scorer, '--source-id'], cwd=ROOT, text=True).strip()
    assert source == SOURCE, 'review applies to a different source snapshot'
    scoped = json.loads((HERE / 'qa-iteration-acceptance.json').read_bytes())
    assert scoped['source_id'] == SOURCE
    assert scoped['acceptance_plan_sha256'] == sha(HERE / 'acceptance.md')
    assert scoped['corrigendum_sha256'] == sha(HERE / 'corrigendum.md')
    assert len({item['id'] for item in scoped['criteria']}) == len(scoped['criteria']) == 6
    for item in scoped['criteria']:
        assert item['status'] == 'pass' and item['evidence']
        for cited in item['evidence']:
            path = (ROOT / cited['path']).resolve()
            assert path.is_relative_to(HERE) and sha(path) == cited['sha256']
    print('change acceptance: verified six assessments and their cited evidence')
    for lane in ('final', 'conservative'):
        run = HERE.parents[1] / 'runs' / f'candidate-296b427a-{lane}.json'
        ledger = json.loads(run.read_bytes())
        result = subprocess.run([*scorer, '--run', run], cwd=ROOT, capture_output=True)
        assert result.returncode == 1, (result.returncode, result.stderr)
        assert json.loads(result.stdout) == json.loads((HERE / f'{lane}-score.json').read_bytes())
        count = 0
        for observation in ledger['observations'].values():
            for cited in observation.get('evidence', []):
                data = (ROOT / cited['path']).resolve()
                receipt = (ROOT / cited['receipt_path']).resolve()
                assert data.is_relative_to(HERE) and receipt.is_relative_to(HERE)
                proof = json.loads(receipt.read_bytes())
                assert proof['source_before'] == proof['source_after'] == cited['source_id'] == SOURCE
                assert proof['exit_code'] == cited['exit_code']
                assert proof['log'] == cited['path'] and sha(data) == proof['sha256'] == cited['sha256']
                assert datetime.fromisoformat(proof['started_utc']) <= datetime.fromisoformat(proof['finished_utc'])
                count += 1
        print(f'{lane}: verified {len(ledger["observations"])} observations and {count} evidence references')


if __name__ == '__main__':
    main()
