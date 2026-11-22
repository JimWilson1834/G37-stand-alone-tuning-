import unittest

from g37offline.transport import parse


def encode(payload, channel="can0", can_id="7E8", direction="", timestamp=True):
    frames = []
    if len(payload) <= 7:
        frames.append(bytes([len(payload)]) + payload)
    else:
        frames.append(bytes([0x10 | (len(payload) >> 8), len(payload) & 255]) + payload[:6])
        for n, start in enumerate(range(6, len(payload), 7), 1):
            frames.append(bytes([0x20 | (n & 15)]) + payload[start:start + 7])
    return [(f"(123.456000) " if timestamp else "") + f"{channel} {direction + ' ' if direction else ''}{can_id}#{frame.hex().upper():0<16}"
            for frame in frames]


class TransportTests(unittest.TestCase):
    def test_sequence_wrap_and_padding(self):
        payload = b"\x63" + bytes(range(140))
        c = parse("\n".join(encode(payload)))
        self.assertEqual([m.data for m in c.messages], [payload])
        self.assertEqual(c.counts["sequence_errors"], 0)
        self.assertEqual(c.frames[0].reference()["timestamp_decimal_places"], 6)

    def test_single_frame_short_tail_and_spaced(self):
        raw = "(123.000) can0 7E8#0763010203040506"
        spaced = "can0 7E8 [8] 07 63 01 02 03 04 05 06"
        self.assertEqual(parse(raw).messages[0].data, b"\x63\x01\x02\x03\x04\x05\x06")
        self.assertEqual(parse(raw).messages[0].data, parse(spaced).messages[0].data)

    def test_bad_dlc_hex_and_can_fd(self):
        for text in ["can0 7E8 [7] 01 43", "can0 7E8#01G3", "can0 7E8#101122334455667788", "can0 7E8#1", "can0 20000000#0143", "can0 7E8##10143"]:
            with self.subTest(text=text):
                c = parse(text)
                self.assertEqual(c.counts["malformed_lines"], 1)
                self.assertEqual(len(c.messages), 0)

    def test_orphan_wrong_sequence_and_truncation(self):
        frames = encode(b"\x63" + b"A" * 30)
        self.assertEqual(parse(frames[1]).counts["orphan_frames"], 1)
        wrong = frames[:2]
        wrong[1] = wrong[1].replace("#21", "#22")
        c = parse("\n".join(wrong))
        self.assertEqual(c.counts["sequence_errors"], 1)
        self.assertFalse(c.messages)
        self.assertEqual(parse(frames[0]).counts["truncated_messages"], 1)
        self.assertEqual(parse("can0 7E8#076301").counts["truncated_messages"], 1)

    def test_new_first_and_single_interrupt_partial(self):
        frames = encode(b"\x63" + b"A" * 30)
        c = parse("\n".join(frames[:1] + frames))
        self.assertEqual(c.counts["interrupted_messages"], 1)
        self.assertEqual(len(c.messages), 1)
        c = parse("\n".join(frames[:1] + encode(b"\x63abc")))
        self.assertEqual(c.counts["interrupted_messages"], 1)
        self.assertEqual(c.messages[0].data, b"\x63abc")

    def test_channels_directions_sessions(self):
        a = encode(b"\x63" + b"A" * 30)
        b = encode(b"\x63" + b"B" * 30, channel="can1")
        c = parse("\n".join(v for pair in zip(a, b) for v in pair))
        self.assertEqual({m.data for m in c.messages}, {b"\x63" + b"A" * 30, b"\x63" + b"B" * 30})
        direction = encode(b"\x63" + b"B" * 30, direction="TX")
        c = parse("\n".join(v for pair in zip(a, direction) for v in pair))
        self.assertEqual(len(c.messages), 2)
        c = parse("\n".join(a[:1] + ["# session second"] + a[1:]))
        self.assertFalse(c.messages)
        self.assertGreater(c.counts["orphan_frames"], 0)

    def test_duplicate_and_conflicting_cf(self):
        frames = encode(b"\x63" + bytes(range(30)))
        c = parse("\n".join(frames[:2] + [frames[1]] + frames[2:]))
        self.assertEqual(len(c.messages), 1)
        self.assertEqual(c.counts["duplicate_frames"], 1)
        corrupt = frames[1][:-2] + "FF"
        c = parse("\n".join(frames[:2] + [corrupt] + frames[2:]))
        self.assertFalse(c.messages)
        self.assertEqual(c.counts["conflicting_frames"], 1)

    def test_control_and_unrelated(self):
        c = parse("can0 7E0#300000FFFFFFFFFF\ncan0 100#FF0102")
        self.assertEqual(c.counts["flow_control_frames"], 1)
        self.assertEqual(c.counts["unrelated_frames"], 1)
        self.assertFalse(c.messages)

    def test_already_reassembled(self):
        c = parse("can0 7E8 PDU 63AABB", reassembled=True)
        self.assertEqual(c.counts["message_lines"], 1)
        self.assertEqual(c.messages[0].data, b"\x63\xaa\xbb")
