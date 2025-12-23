from pqcdualusb.security import SecureMemory

print("Testing SecureMemory...")
try:
    with SecureMemory(1024) as buf:
        buf[:5] = b'hello'
        print(f"Buffer works: {bytes(buf[:5])}")
    print("✅ Context manager works")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
