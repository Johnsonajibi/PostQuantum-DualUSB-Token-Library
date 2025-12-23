from pqcdualusb import PostQuantumCrypto

c = PostQuantumCrypto()
print(f"Backend: {c.backend}")

# Generate keypair
sk, pk = c.generate_kem_keypair()
print(f"After generate_kem_keypair:")
print(f"  sk length: {len(sk)}")
print(f"  pk length: {len(pk)}")

# Encapsulate
ct, ss1 = c.kem_encapsulate(pk)
print(f"\nAfter kem_encapsulate(pk):")
print(f"  ct length: {len(ct)}")
print(f"  ss1 length: {len(ss1)}")

# Try to decapsulate - let's add debugging
print(f"\nCalling kem_decapsulate(secret_key={len(sk)}, ciphertext={len(ct)})")

# Check method signature
import inspect
sig = inspect.signature(c.kem_decapsulate)
print(f"Method signature: {sig}")
print(f"Parameters: {list(sig.parameters.keys())}")

# Now actually call it
try:
    ss2 = c.kem_decapsulate(sk, ct)
    print(f"Success! ss2 length: {len(ss2)}")
    print(f"Match: {ss1 == ss2}")
except Exception as e:
    print(f"Error: {e}")
    
    # Let's try with args explicitly named
    print("\nTrying with explicit parameter names...")
    try:
        ss2 = c.kem_decapsulate(secret_key=sk, ciphertext=ct)
        print(f"Success! ss2 length: {len(ss2)}")
    except Exception as e2:
        print(f"Still failed: {e2}")
