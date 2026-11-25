"""Run:  python -m unittest discover tests"""
import os
import unittest

from src.detector import Detector
from src.features import extract_features
from src.samples import SIMULATED_EVENTS


class PipelineTests(unittest.TestCase):
    def test_features_detect_encoded_hidden_powershell(self):
        f = extract_features(SIMULATED_EVENTS[0])
        self.assertEqual((f["has_encoded_cmd"], f["hidden_window"], f["parent_is_office"]), (1, 1, 1))

    def test_benign_admin_command_has_no_encoding(self):
        f = extract_features(SIMULATED_EVENTS[3])
        self.assertEqual((f["has_encoded_cmd"], f["download_cradle"]), (0, 0))

    @unittest.skipUnless(os.path.exists("models/rf_model.joblib"), "run train.py first")
    def test_detector_flags_simulated_attacks_and_not_benign(self):
        res = Detector().score(SIMULATED_EVENTS).set_index("pid")
        for pid in (90001, 90002, 90003):
            self.assertNotEqual(res.loc[pid, "verdict"], "BENIGN")
        for pid in (90004, 90005):
            self.assertEqual(res.loc[pid, "verdict"], "BENIGN")


if __name__ == "__main__":
    unittest.main()
