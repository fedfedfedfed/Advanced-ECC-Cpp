#include <iostream>
#include <vector>
#include <random>
#include <ctime>
#include <cstring>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

using namespace std;

const unsigned long long SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FULL;
const unsigned long long SECP256K1_A = 0;
const unsigned long long SECP256K1_B = 7;
const unsigned long long SECP256K1_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240ULL;
const unsigned long long SECP256K1_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424ULL;
const unsigned long long SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141ULL;

unsigned long long generate_secure_random_scalar(unsigned long long min, unsigned long long max) {
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<unsigned long long> dis(min, max);
    return dis(gen);
}

inline unsigned long long modp(long long x, unsigned long long p) {
    long long r = x % (long long)p;
    if (r < 0) r += p;
    return (unsigned long long)r;
}

inline unsigned long long modp_add(unsigned long long a, unsigned long long b, unsigned long long p) {
    return (a + b) % p;
}

inline unsigned long long modp_sub(unsigned long long a, unsigned long long b, unsigned long long p) {
    long long r = (long long)a - (long long)b;
    if (r < 0) r += p;
    return (unsigned long long)r;
}

inline unsigned long long modp_mul(unsigned long long a, unsigned long long b, unsigned long long p) {
    __int128 result = (__int128)a * (__int128)b;
    return (unsigned long long)(result % p);
}

unsigned long long modp_inv(unsigned long long a, unsigned long long p) {
    long long t = 0, newt = 1;
    long long r = (long long)p, newr = (long long)a;
    
    while (newr != 0) {
        long long quotient = r / newr;
        long long temp = t;
        t = newt;
        newt = temp - quotient * newt;
        
        temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }

    if (r > 1) {
        throw invalid_argument("a is not invertible");
    }
    if (t < 0) {
        t += (long long)p;
    }

    return (unsigned long long)t;
}

inline unsigned long long modp_div(unsigned long long a, unsigned long long b, unsigned long long p) {
    unsigned long long invb = modp_inv(b, p);
    return modp_mul(a, invb, p);
}

struct ECPoint {
    unsigned long long x;
    unsigned long long y;
    bool isInfinity;

    ECPoint() : x(0), y(0), isInfinity(true) {}
    ECPoint(unsigned long long x_, unsigned long long y_) : x(x_), y(y_), isInfinity(false) {}

    void print() const {
        if (isInfinity) {
            cout << "Point(Infinity)\n";
        } else {
            cout << "Point(0x" << hex << x << ", 0x" << y << dec << ")\n";
        }
    }

    string serialize() const {
        if (isInfinity) {
            return "Infinity";
        } else {
            stringstream ss;
            ss << hex << x << y;
            return ss.str();
        }
    }

    string compress() const {
        if (isInfinity) {
            return "Infinity";
        } else {
            stringstream ss;
            ss << hex << x << (y % 2 ? "1" : "0");
            return ss.str();
        }
    }

    static ECPoint decompress(unsigned long long x, bool y_parity, unsigned long long a, unsigned long long b, unsigned long long p) {
        unsigned long long rhs = modp_add(modp_mul(modp_mul(x, x, p), x, p), modp_mul(a, x, p), p);
        rhs = modp_add(rhs, b, p);

        for (unsigned long long y = 0; y < p; y++) {
            if (modp_mul(y, y, p) == rhs) {
                if (y % 2 == y_parity) {
                    return ECPoint(x, y);
                } else {
                    return ECPoint(x, modp_sub(0, y, p));
                }
            }
        }
        throw invalid_argument("No valid y found for the given x and parity");
    }
};

bool is_on_curve(const ECPoint &Pnt, unsigned long long a, unsigned long long b, unsigned long long p) {
    if (Pnt.isInfinity) return true;
    unsigned long long lhs = modp_mul(Pnt.y, Pnt.y, p);
    unsigned long long rhs = modp_add(modp_mul(modp_mul(Pnt.x, Pnt.x, p), Pnt.x, p), modp_mul(a, Pnt.x, p), p);
    rhs = modp_add(rhs, b, p);
    return (lhs == rhs);
}

ECPoint ec_double(const ECPoint &P1, unsigned long long a, unsigned long long b, unsigned long long p) {
    if (P1.isInfinity) return P1;

    unsigned long long s_num = modp_add(modp_mul(3, modp_mul(P1.x, P1.x, p), p), a, p);
    unsigned long long s_den = modp_mul(2, P1.y, p);
    if (s_den == 0) {
        return ECPoint();
    }
    unsigned long long s = modp_div(s_num, s_den, p);

    unsigned long long x3 = modp_sub(modp_mul(s, s, p), P1.x, p);
    x3 = modp_sub(x3, P1.x, p);

    unsigned long long y3 = modp_mul(s, modp_sub(P1.x, x3, p), p);
    y3 = modp_sub(y3, P1.y, p);

    return ECPoint(x3, y3);
}

ECPoint ec_add(const ECPoint &P1, const ECPoint &P2, unsigned long long a, unsigned long long b, unsigned long long p) {
    if (P1.isInfinity) return P2;
    if (P2.isInfinity) return P1;

    if (P1.x == P2.x) {
        if (P1.y != P2.y) {
            return ECPoint();
        } else {
            return ec_double(P1, a, b, p);
        }
    }

    unsigned long long s_num = modp_sub(P2.y, P1.y, p);
    unsigned long long s_den = modp_sub(P2.x, P1.x, p);
    unsigned long long s = modp_div(s_num, s_den, p);

    unsigned long long x3 = modp_mul(s, s, p);
    x3 = modp_sub(x3, P1.x, p);
    x3 = modp_sub(x3, P2.x, p);

    unsigned long long y3 = modp_mul(s, modp_sub(P1.x, x3, p), p);
    y3 = modp_sub(y3, P1.y, p);

    return ECPoint(x3, y3);
}

ECPoint ec_scalar_mul(unsigned long long k, const ECPoint &P, unsigned long long a, unsigned long long b, unsigned long long p) {
    ECPoint result;
    ECPoint addend = P;

    while (k > 0) {
        if (k & 1ULL) {
            result = ec_add(result, addend, a, b, p);
        }
        addend = ec_double(addend, a, b, p);
        k >>= 1ULL;
    }

    return result;
}

struct KeyPair {
    unsigned long long privKey;
    ECPoint pubKey;

    static KeyPair generate(const ECPoint &G, unsigned long long a, unsigned long long b, unsigned long long p) {
        KeyPair kp;
        kp.privKey = generate_secure_random_scalar(1, SECP256K1_ORDER - 1);
        kp.pubKey = ec_scalar_mul(kp.privKey, G, a, b, p);
        return kp;
    }
};

struct ECDSASignature {
    unsigned long long r;
    unsigned long long s;

    string serialize() const {
        stringstream ss;
        ss << hex << r << s;
        return ss.str();
    }

    void print() const {
        cout << "Signature(r=0x" << hex << r << ", s=0x" << s << dec << ")\n";
    }
};

unsigned long long sha256_hash(const string &message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message.c_str(), message.size(), hash);
    unsigned long long hash_val = 0;
    for (int i = 0; i < 8; i++) {
        hash_val = (hash_val << 8) | hash[i];
    }
    return hash_val;
}

ECDSASignature ecdsa_sign(const string &message, const KeyPair &signer, const ECPoint &G, unsigned long long a, unsigned long long b, unsigned long long p) {
    ECDSASignature sig;
    unsigned long long z = sha256_hash(message);
    unsigned long long k;
    ECPoint R;
    do {
        k = generate_secure_random_scalar(1, SECP256K1_ORDER - 1);
        R = ec_scalar_mul(k, G, a, b, p);
        sig.r = R.x % SECP256K1_ORDER;
    } while (sig.r == 0);

    unsigned long long k_inv = modp_inv(k, SECP256K1_ORDER);
    sig.s = (modp_mul(z, k_inv, SECP256K1_ORDER) + modp_mul(signer.privKey, sig.r, SECP256K1_ORDER)) % SECP256K1_ORDER;
    if (sig.s == 0) {
        throw runtime_error("Invalid signature: s cannot be zero");
    }
    return sig;
}

bool ecdsa_verify(const string &message, const ECDSASignature &sig, const ECPoint &signer_pubKey, const ECPoint &G, unsigned long long a, unsigned long long b, unsigned long long p) {
    if (sig.r <= 0 || sig.r >= SECP256K1_ORDER || sig.s <= 0 || sig.s >= SECP256K1_ORDER) {
        return false;
    }

    unsigned long long z = sha256_hash(message);
    unsigned long long s_inv = modp_inv(sig.s, SECP256K1_ORDER);
    unsigned long long u1 = modp_mul(z, s_inv, SECP256K1_ORDER);
    unsigned long long u2 = modp_mul(sig.r, s_inv, SECP256K1_ORDER);

    ECPoint point1 = ec_scalar_mul(u1, G, a, b, p);
    ECPoint point2 = ec_scalar_mul(u2, signer_pubKey, a, b, p);
    ECPoint R = ec_add(point1, point2, a, b, p);

    if (R.isInfinity) return false;
    return (R.x % SECP256K1_ORDER) == sig.r;
}

unsigned long long ecdh_shared_secret(const KeyPair &alice, const KeyPair &bob, unsigned long long a, unsigned long long b, unsigned long long p) {
    ECPoint shared_point = ec_scalar_mul(alice.privKey, bob.pubKey, a, b, p);
    return shared_point.x; 
}

int main() {
    try {
        unsigned long long p = SECP256K1_P;
        unsigned long long a = SECP256K1_A;
        unsigned long long b = SECP256K1_B;

        ECPoint G;
        G.x = SECP256K1_Gx;
        G.y = SECP256K1_Gy;
        G.isInfinity = false;

        cout << "=== Advanced ECC DEMO ===" << endl;
        cout << "Curve: y^2 = x^3 + " << a << "*x + " << b << " (mod p)\n";
        cout << "Base Point G: ";
        G.print();
        cout << "Order of G: " << SECP256K1_ORDER << "\n\n";

        if (!is_on_curve(G, a, b, p)) {
            throw runtime_error("Base point G is not on the curve.");
        }

        cout << "Generating Alice's KeyPair..." << endl;
        KeyPair alice = KeyPair::generate(G, a, b, p);
        cout << "Alice's Private Key: " << alice.privKey << endl;
        cout << "Alice's Public Key: ";
        alice.pubKey.print();
        cout << endl;

        cout << "Generating Bob's KeyPair..." << endl;
        KeyPair bob = KeyPair::generate(G, a, b, p);
        cout << "Bob's Private Key: " << bob.privKey << endl;
        cout << "Bob's Public Key: ";
        bob.pubKey.print();
        cout << endl;

        cout << "Computing ECDH Shared Secret..." << endl;
        unsigned long long shared_alice = ecdh_shared_secret(alice, bob, a, b, p);
        unsigned long long shared_bob   = ecdh_shared_secret(bob, alice, a, b, p);
        cout << "Alice's computed shared secret: " << shared_alice << endl;
        cout << "Bob's   computed shared secret: " << shared_bob << endl;
        if (shared_alice == shared_bob) {
            cout << "[OK] Shared secrets match. ECDH successful!\n\n";
        } else {
            cout << "[FAIL] Shared secrets do not match.\n\n";
        }

        cout << "=== ECDSA Signing ===" << endl;
        string message = "Hello, this is a secure message!";
        cout << "Message: " << message << endl;

        ECDSASignature signature = ecdsa_sign(message, alice, G, a, b, p);
        cout << "Generated Signature: ";
        signature.print();
        cout << endl;

        cout << "Verifying Signature..." << endl;
        bool is_valid = ecdsa_verify(message, signature, alice.pubKey, G, a, b, p);
        cout << "Signature is " << (is_valid ? "valid." : "invalid.") << "\n\n";

        cout << "=== ECC Encryption / Decryption ===" << endl;

        ECPoint messagePoint;
        messagePoint.isInfinity = false;
        bool found = false;
        for (unsigned long long xTry = 1; xTry < 1000000; xTry++) {
            unsigned long long rhs = modp_add(modp_mul(modp_mul(xTry, xTry, p), xTry, p), modp_mul(a, xTry, p), p);
            rhs = modp_add(rhs, b, p);
            unsigned long long y_try = 0;
            bool y_found = false;
            for (; y_try < p; y_try++) {
                if (modp_mul(y_try, y_try, p) == rhs) {
                    y_found = true;
                    break;
                }
            }
            if (y_found) {
                messagePoint.x = xTry;
                messagePoint.y = y_try;
                if (is_on_curve(messagePoint, a, b, p)) {
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            throw runtime_error("Failed to find a valid message point on the curve.");
        }

        cout << "Message Point (M): ";
        messagePoint.print();

        unsigned long long k = generate_secure_random_scalar(1, SECP256K1_ORDER - 1);
        ECPoint R = ec_scalar_mul(k, G, a, b, p);
        ECPoint k_pub = ec_scalar_mul(k, bob.pubKey, a, b, p);
        ECPoint C = ec_add(messagePoint, k_pub, a, b, p);

        cout << "Ciphertext:" << endl;
        cout << " R = "; R.print();
        cout << " C = "; C.print();
        cout << endl;

        ECPoint priv_R = ec_scalar_mul(bob.privKey, R, a, b, p);
        ECPoint minus_priv_R;
        minus_priv_R.x = priv_R.x;
        minus_priv_R.y = modp_sub(0, priv_R.y, p);
        minus_priv_R.isInfinity = priv_R.isInfinity;

        ECPoint recovered = ec_add(C, minus_priv_R, a, b, p);
        cout << "Recovered Message: ";
        recovered.print();

        if (recovered.x == messagePoint.x && recovered.y == messagePoint.y && recovered.isInfinity == messagePoint.isInfinity) {
            cout << "[OK] Decryption successful. Message matches.\n";
        } else {
            cout << "[FAIL] Decryption failed. Message does not match.\n";
        }

        cout << "\n=== Point Compression and Decompression ===" << endl;
        string compressed = alice.pubKey.compress();
        cout << "Alice's Compressed Public Key: " << compressed << endl;

        unsigned long long compressed_x;
        bool y_parity;
        string compressed_str = compressed;
        string x_hex = compressed_str.substr(0, compressed_str.size() - 1);
        char parity_char = compressed_str.back();
        y_parity = (parity_char == '1') ? true : false;
        unsigned long long x_val = 0;
        stringstream ss(x_hex);
        ss << hex;
        ss >> x_val;

        ECPoint decompressed = ECPoint::decompress(x_val, y_parity, a, b, p);
        cout << "Decompressed Public Key: ";
        decompressed.print();

        if (decompressed.x == alice.pubKey.x && decompressed.y == alice.pubKey.y) {
            cout << "[OK] Point decompression successful.\n";
        } else {
            cout << "[FAIL] Point decompression mismatch.\n";
        }

        cout << "\n=== End of Advanced ECC Demo ===" << endl;
    }
    catch (const exception &e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
