import unittest
from pathlib import Path
from telemetry import emit, load_contract, parse_sample

class TelemetryFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract=load_contract(Path(__file__).resolve().parents[1]/"protocol/telemetry/telemetry-v1.yaml"); cls.metric=next(m for m in contract["metrics"] if m["name"]=="noos_p2p_peers")
    def test_emitter_parser_numeric(self):
        line=emit("noos_p2p_peers",4,{"direction":"inbound"},100_000)
        self.assertEqual(parse_sample(line,self.metric,now_seconds=101).value,4)
    def test_stale_is_unknown_not_zero(self):
        result=parse_sample('noos_p2p_peers{direction="inbound"} 0 10000',self.metric,now_seconds=100)
        self.assertEqual((result.state,result.reason),("UNKNOWN","stale")); self.assertIsNone(result.value)
    def test_malformed_and_unbounded_label_are_unknown(self):
        self.assertEqual(parse_sample('noos_p2p_peers{txid="abc"} 9 100000',self.metric,101).state,"UNKNOWN")
        self.assertEqual(parse_sample('noos_p2p_peers{direction="inbound"} NaN 100000',self.metric,101).state,"UNKNOWN")
    def test_absent_timestamp_is_unknown(self):
        self.assertEqual(parse_sample('noos_p2p_peers{direction="outbound"} 2',self.metric,101).reason,"absent_timestamp")

if __name__ == "__main__": unittest.main()
