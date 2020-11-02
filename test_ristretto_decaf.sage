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

def testMapRistretto():
    print ("Testing one way map on Ed25519Point")
    vectors = {}

    r = bytearray.fromhex("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46")
    assert P.encode() == exp
    vectors["1"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b")
    assert P.encode() == exp
    vectors["2"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826")
    assert P.encode() == exp
    vectors["3"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a")
    assert P.encode() == exp
    vectors["4"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179")
    assert P.encode() == exp
    vectors["5"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628")
    assert P.encode() == exp
    vectors["6"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982")
    P = Ed25519Point().one_way_map(r)
    exp = bytearray.fromhex("80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065")
    assert P.encode() == exp
    vectors["7"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    return vectors

def main(path="vectors"):
    vectors = {}

    vectors["decaf448"] = testVectorsDecaf()
    vectors["ristretto255"] = testVectorsRistretto()
    vectors["ristretto255_map"] = testMapRistretto()

    with open(path + "/vectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
