"""Replay only provider-error CP4 rows; preserve measured successful outcomes."""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agents.agent import create_red_agent_default
from agents.guards_agent import create_red_agent_advance
from attacks.attacks import adversarial_prompts, run_attacks, write_run_attack_json, save_attack_results

async def main():
    targets = [
        ('red_default', 'unsafe_attack_result.json', create_red_agent_default),
        ('red_advance', 'guards_attack_result.json', create_red_agent_advance),
    ]
    measured = {}
    for target, filename, factory in targets:
        path = ROOT / 'outputs' / filename
        rows = json.loads(path.read_text(encoding='utf-8'))['results']
        failed_ids = {r['id'] for r in rows if r.get('error')}
        if failed_ids:
            print(f'Replaying provider failures for {target}: {sorted(failed_ids)}', flush=True)
            agent, runner = factory()
            fresh = await run_attacks(agent, runner,
                prompts=[p for p in adversarial_prompts if p['id'] in failed_ids],
                target_name=target, save_json=False)
            replacements = {r['id']: r for r in fresh}
            rows = [replacements.get(r['id'], r) for r in rows]
            write_run_attack_json(rows, target_name=target)
        measured[target] = rows
    save_attack_results(unsafe_results=measured['red_default'], guards_results=measured['red_advance'])
    print('Remaining provider-error rows:', sum(bool(r.get('error')) for rows in measured.values() for r in rows))

if __name__ == '__main__':
    asyncio.run(main())