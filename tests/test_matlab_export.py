"""Reproducibility, raw-XOR and candidate-accounting checks for MATLAB data."""
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import export_matlab as exporter


class ExportTests(unittest.TestCase):
    def test_campaign_and_reproducibility(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            meta = exporter.export_campaign(first, trials=3, observations=4, seed=42)
            exporter.export_campaign(second, trials=3, observations=4, seed=42)
            self.assertEqual(meta['status'], 'complete')
            for name in ('propagation', 'candidates', 'recovery', 'inputs'):
                path = Path(first) / (name + '.csv')
                self.assertEqual(path.read_bytes(), (Path(second) / path.name).read_bytes())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), meta['csv_sha256'][path.name])
            with (Path(first) / 'propagation.csv').open() as stream:
                propagation = list(csv.DictReader(stream))
            self.assertEqual(len(propagation), 3 * 13)
            for row in propagation:
                delta = bytes(a ^ b for a, b in zip(bytes.fromhex(row['correct_hex']), bytes.fromhex(row['faulty_hex'])))
                self.assertEqual(sum(bin(v).count('1') for v in delta), int(row['changed_bits']))
                self.assertEqual(sum(bool(v) for v in delta), int(row['changed_bytes']))
                self.assertEqual(list(delta), [int(row[field]) for field in exporter.DELTA_FIELDS[:len(delta)]])
            first_aes = [row for row in propagation if row['algorithm'] == 'AES' and row['trial'] == '1']
            self.assertEqual([int(row['changed_bytes']) for row in first_aes], [0, 1, 4, 4, 4, 4, 4])
            with (Path(first) / 'candidates.csv').open() as stream:
                candidates = list(csv.DictReader(stream))
            self.assertEqual(len(candidates), 2 * 3 * 4 * 5)
            for algorithm, prior in [('AES', 2**32), ('SM4', 256)]:
                for trial in range(1, 4):
                    for group in range(4):
                        rows = [row for row in candidates if row['algorithm'] == algorithm and int(row['trial']) == trial and int(row['group']) == group]
                        counts = [int(row['candidate_count']) for row in rows]
                        self.assertEqual(counts[0], prior)
                        self.assertTrue(all(a >= b >= 1 for a, b in zip(counts, counts[1:])))
                        for row in rows[1:]:
                            if row['evaluated'] == '0':
                                self.assertEqual(row['candidate_count'], '1')
                                self.assertEqual(row['faulty_hex'], '')

    def test_ambiguous_trials_are_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            exporter.export_campaign(folder, trials=2, observations=1)
            with (Path(folder) / 'recovery.csv').open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertTrue(all(row['all_groups_unique'] == '0' for row in rows))


if __name__ == '__main__':
    unittest.main(verbosity=2)
