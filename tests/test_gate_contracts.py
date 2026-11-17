import json
import unittest
from pathlib import Path


GATES_PATH = Path(__file__).resolve().parents[1] / "docs" / "testing" / "gates.json"
ALLOWED_STATUSES = {
    "PLANNED",
    "IN_PROGRESS",
    "IMPLEMENTED",
    "TESTED",
    "VERIFIED",
    "CERTIFIED",
    "LOCKED",
}
REQUIRED_GATE_FIELDS = {
    "id",
    "name",
    "status",
    "objective",
    "source_contracts",
    "acceptance_criteria",
    "lock_conditions",
}
REQUIRED_CRITERION_FIELDS = {"id", "requirement", "evidence"}


class GateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with GATES_PATH.open("r", encoding="utf-8") as handle:
            cls.spec = json.load(handle)

    def test_schema_and_gate_ids_are_valid(self):
        self.assertEqual(self.spec.get("schema_version"), "1.0")
        self.assertIsInstance(self.spec.get("gates"), list)
        self.assertGreater(len(self.spec["gates"]), 0)

        gate_ids = []
        for gate in self.spec["gates"]:
            self.assertTrue(REQUIRED_GATE_FIELDS.issubset(gate))
            self.assertIn(gate["status"], ALLOWED_STATUSES)
            self.assertTrue(gate["id"].strip())
            self.assertTrue(gate["objective"].strip())
            self.assertIsInstance(gate["source_contracts"], list)
            self.assertGreater(len(gate["source_contracts"]), 0)
            self.assertIsInstance(gate["acceptance_criteria"], list)
            self.assertGreater(len(gate["acceptance_criteria"]), 0)
            self.assertIsInstance(gate["lock_conditions"], list)
            self.assertGreater(len(gate["lock_conditions"]), 0)
            gate_ids.append(gate["id"])

        self.assertEqual(len(gate_ids), len(set(gate_ids)))
        self.assertIn("P1.1", gate_ids)
        self.assertIn("GATE4", gate_ids)

    def test_acceptance_criteria_are_complete_and_unique(self):
        criterion_ids = []
        for gate in self.spec["gates"]:
            for criterion in gate["acceptance_criteria"]:
                self.assertTrue(REQUIRED_CRITERION_FIELDS.issubset(criterion))
                self.assertTrue(criterion["id"].strip())
                self.assertTrue(criterion["requirement"].strip())
                self.assertIsInstance(criterion["evidence"], list)
                self.assertGreater(len(criterion["evidence"]), 0)
                criterion_ids.append(criterion["id"])

        self.assertEqual(len(criterion_ids), len(set(criterion_ids)))

    def test_source_contracts_exist_in_repository(self):
        repository_root = GATES_PATH.parents[2]
        for gate in self.spec["gates"]:
            for contract in gate["source_contracts"]:
                contract_path = repository_root / contract
                self.assertTrue(
                    contract_path.is_file(),
                    f"Missing source contract for {gate['id']}: {contract}",
                )


if __name__ == "__main__":
    unittest.main()
