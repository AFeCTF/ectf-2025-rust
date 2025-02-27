from ectf25.utils.decoder import DecoderIntf
from ectf25_design.gen_subscription import gen_subscription
import unittest
import argparse
import sys
import time

def new_subscription(device_id: int, start: int, end: int, channel: int) -> bytes:
    return gen_subscription(secrets, device_id, start, end, channel)

class TestDecoder(unittest.TestCase):
    def testList(self):
        decoder.list()

    def testSubscribe(self):
        global decoder
        test_subs = [
            (1, 123456789, 387654321),
            (4294967295, 23456789, 498700020),
            (4294967290, 33456789, 5498700020),
            (4294967285, 23456789, 65498700020),
            (1000, 410000000, 9298800020),
            (40000, 12456789, 23493511120),
            (600000, 53456789, 91498998823),
            (2000000000, 0, 18446744073709551615)
        ]

        for s in test_subs:
            sub = new_subscription(0xdeadbeef, s[1], s[2], s[0])
            decoder.subscribe(sub)

        channels = set(decoder.list())
        self.assertGreaterEqual(channels, set(test_subs))

        input("power cycle...")
        decoder = DecoderIntf(args.port)

        channels = set(decoder.list())
        self.assertGreaterEqual(channels, set(test_subs))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "port",
        help="Serial port to the Decoder (see https://rules.ectf.mitre.org/2025/getting_started/boot_reference for platform-specific instructions)",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )

    args = parser.parse_args()
    secrets = args.secrets_file.read()
    decoder = DecoderIntf(args.port)

    del sys.argv[1]
    del sys.argv[1]

    unittest.main()

