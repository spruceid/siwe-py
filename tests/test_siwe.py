import unittest
import json

from siwe.siwe import SiweMessage


class MessageGeneration(unittest.TestCase):
    def test_valid_message(self):
        with open('data/parsing_positive.json', 'r') as f:
            data = json.load(fp=f)

        for desc, value in data.items():
            siwe_message = SiweMessage(message=value["fields"])
            self.assertEqual(siwe_message.to_message(), value["message"], f"'{value['message']}' message incorrect.")

    def test_invalid_message(self):
        # TODO: Add Invalid message tests for catching exceptions
        self.assertTrue(True, "Not implemented.")


class MessageValidation(unittest.TestCase):
    def test_valid_message(self):
        self.assertTrue(False, "Validation not yet implemented.")

    def test_invalid_message(self):
        self.assertTrue(False, "Validation not yet implemented.")


class MessageRoundTrip(unittest.TestCase):
    def test_message_round_trip(self):
        self.assertTrue(False, "Validation not yet implemented.")


if __name__ == '__main__':
    unittest.main()
