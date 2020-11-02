#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.formulas import Ed25519Point, Ed448GoldilocksPoint
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)

def testVectorsRistretto():
    print("Testing with Ristretto255 on Ed25519Point")
    vector = []

    P = Ed25519Point.base()
    Q = Ed25519Point(0)
    R = bytearray(32)
    for i in range(16):
        assert Q.encode() == R
        vector.append(to_hex(Q.encode()))
        Q += P
        R = bytearray(Q.encode())

    return vector

def testVectorsDecaf():
    print("Testing with Ristretto255 on Ed25519Point")
    vector = []

    P = Ed448GoldilocksPoint.base()
    Q = Ed448GoldilocksPoint(0)
    R = bytearray(56)
    for i in range(16):
        assert Q.encode() == R
        vector.append(to_hex(Q.encode()))
        Q += P
        R = bytearray(Q.encode())

    return vector

def main(path="vectors"):
    vectors = {}

    vectors["ristretto255"] = testVectorsRistretto()
    vectors["decaf448"] = testVectorsDecaf()

    with open(path + "/vectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
