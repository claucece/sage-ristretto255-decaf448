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

def testMapDecaf():
    print ("Testing one way map on Ed448Goldilocks")
    vectors = {}

    r = bytearray.fromhex("cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165d5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b26bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("0c709c9607dbb01c94513358745b7c23953d03b33e39c7234e268d1d6e24f34014ccbc2216b965dd231d5327e591dc3c0e8844ccfd568848")
    assert P.encode() == exp
    vectors["1"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("b6d8da654b13c3101d6634a231569e6b85961c3f4b460a08ac4a5857069576b64428676584baa45b97701be6d0b0ba18ac28d443403b45699ea0fbd1164f5893d39ad8f29e48e399aec5902508ea95e33bc1e9e4620489d684eb5c26bc1ad1e09aba61fabc2cdfee0b6b6862ffc8e55a")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("76ab794e28ff1224c727fa1016bf7f1d329260b7218a39aea2fdb17d8bd9119017b093d641cedf74328c327184dc6f2a64bd90eddccfcdab")
    assert P.encode() == exp
    vectors["2"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("36a69976c3e5d74e4904776993cbac27d10f25f5626dd45c51d15dcf7b3e6a5446a6649ec912a56895d6baa9dc395ce9e34b868d9fb2c1fc72eb6495702ea4f446c9b7a188a4e0826b1506b0747a6709f37988ff1aeb5e3788d5076ccbb01a4bc6623c92ff147a1e21b29cc3fdd0e0f4")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("c8d7ac384143500e50890a1c25d643343accce584caf2544f9249b2bf4a6921082be0e7f3669bb5ec24535e6c45621e1f6dec676edd8b664")
    assert P.encode() == exp
    vectors["3"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("d5938acbba432ecd5617c555a6a777734494f176259bff9dab844c81aadcf8f7abd1a9001d89c7008c1957272c1786a4293bb0ee7cb37cf3988e2513b14e1b75249a5343643d3c5e5545a0c1a2a4d3c685927c38bc5e5879d68745464e2589e000b31301f1dfb7471a4f1300d6fd0f99")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("62beffc6b8ee11ccd79dbaac8f0252c750eb052b192f41eeecb12f2979713b563caf7d22588eca5e80995241ef963e7ad7cb7962f343a973")
    assert P.encode() == exp
    vectors["4"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("4dec58199a35f531a5f0a9f71a53376d7b4bdd6bbd2904234a8ea65bbacbce2a542291378157a8f4be7b6a092672a34d85e473b26ccfbd4cdc6739783dc3f4f6ee3537b7aed81df898c7ea0ae89a15b5559596c2a5eeacf8b2b362f3db2940e3798b63203cae77c4683ebaed71533e51")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("f4ccb31d263731ab88bed634304956d2603174c66da38742053fa37dd902346c3862155d68db63be87439e3d68758ad7268e239d39c4fd3b")
    assert P.encode() == exp
    vectors["5"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("df2aa1536abb4acab26efa538ce07fd7bca921b13e17bc5ebcba7d1b6b733deda1d04c220f6b5ab35c61b6bcb15808251cab909a01465b8ae3fc770850c66246d5a9eae9e2877e0826e2b8dc1bc08009590bc6778a84e919fbd28e02a0f9c49b48dc689eb5d5d922dc01469968ee81b5")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("7e79b00e8e0a76a67c0040f62713b8b8c6d6f05e9c6d02592e8a22ea896f5deacc7c7df5ed42beae6fedb9000285b482aa504e279fd49c32")
    assert P.encode() == exp
    vectors["6"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    r = bytearray.fromhex("e9fb440282e07145f1f7f5ecf3c273212cd3d26b836b41b02f108431488e5e84bd15f2418b3d92a3380dd66a374645c2a995976a015632d36a6c2189f202fc766e1c82f50ad9189be190a1f0e8f9b9e69c9c18cc98fdd885608f68bf0fdedd7b894081a63f70016a8abf04953affbefa")
    P = Ed448GoldilocksPoint().one_way_map(r)
    exp = bytearray.fromhex("20b171cb16be977f15e013b9752cf86c54c631c4fc8cbf7c03c4d3ac9b8e8640e7b0e9300b987fe0ab5044669314f6ed1650ae037db853f1")
    assert P.encode() == exp
    vectors["7"] = {
        "Input" : to_hex(r),
        "Output" : (to_hex(P.encode()))
    }

    return vectors

def main(path="vectors"):
    vectors = {}

    vectors["decaf448"] = testVectorsDecaf()
    vectors["decaf448_map"] = testMapDecaf()
    vectors["ristretto255"] = testVectorsRistretto()
    vectors["ristretto255_map"] = testMapRistretto()

    with open(path + "/vectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
