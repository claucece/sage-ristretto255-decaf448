try:
    from sagelib.formulas import Ed25519Point, Ed448GoldilocksPoint
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def testVectorsRistrettoDecaf():
    vectors = []

    print("Testing with Ristretto255 on Ed25519Point")
    vector = {}

    P = Ed25519Point.base()
    Q = Ed25519Point(0)
    R = bytearray(32)
    for i in range(16):
        assert Q.encode() == R
        vector["Ristretto255"] = {
            "Multiple " + i: hex(Q.encode())
        }
        Q += P
        R = bytearray(Q.encode())

    print("Testing with Decaf448 on Ed448GoldilocksPoint")
    P = Ed448GoldilocksPoint.base()
    Q = Ed448GoldilocksPoint(0)
    R = bytearray(56)
    for i in range(16):
        assert Q.encode() == R
        vector["Decaf448"]  = {
            "Multiple " + i: hex(Q.encode())
        }
        Q += P
        R = bytearray(Q.encode())

def main(path="vectors"):
    vectors = {}

    testVectorsRistrettoDecaf()

    with open(path + "/vectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
