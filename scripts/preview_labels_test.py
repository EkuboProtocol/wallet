"""Regression cases for the synthetic teacher's value roles."""
import pathlib
import runpy
import unittest

TEACHER = runpy.run_path(str(pathlib.Path(__file__).with_name("preview-labels.py")))


class PreviewLabelsTest(unittest.TestCase):
    def test_transfer_from_keeps_the_complete_decoded_reading(self):
        pieces = TEACHER["summarize"](
            "transfer", [(0, "<action>"), (1, "<address>"), (2, "<address>"), (3, "<amount>")],
            None, "transferFrom sender to recipient for 5 ETH",
        )
        self.assertEqual(pieces, ["<s0>"])

    def test_own_sender_does_not_make_the_recipient_an_owned_account(self):
        example = {
            "formats": [""], "slot_kinds": ["<action>"], "slot_calls": [0],
            "call_descriptions": ["transferFrom sender (your account main) to recipient for 5 ETH"],
            "warnings": [], "has_value": False,
        }
        self.assertEqual(TEACHER["label"](example, {})["risk"], "caution")

    def test_unknown_category_preserves_a_known_action(self):
        pieces = TEACHER["summarize"](
            "unrecognized", [(0, "<protocol>"), (1, "<action>")],
            "Start unstaking", "Threshold Network — Start unstaking",
        )
        self.assertEqual(pieces, ["<s0>", ":", "<s1>"])
        self.assertEqual(TEACHER["risk_of"]("unrecognized", [], False, False, True), "caution")
        self.assertEqual(TEACHER["risk_of"]("unrecognized", [], False, False, False), "critical")


if __name__ == "__main__":
    unittest.main()
