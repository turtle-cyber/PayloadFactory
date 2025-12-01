import requests
import time

BASE_URL = "http://localhost:8000"

def test_api():
    print("Waiting for server to start...")
    for _ in range(10):
        try:
            response = requests.get(f"{BASE_URL}/health")
            if response.status_code == 200:
                print("Server is up!")
                break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    else:
        print("Server failed to start.")
        return

    # Test Scan
    print("\nTesting /api/scan...")
    scan_payload = {"code": "int main() { char buf[10]; strcpy(buf, input); }"}
    try:
        response = requests.post(f"{BASE_URL}/api/scan", json=scan_payload)
        print(f"Scan Response: {response.json()}")
    except Exception as e:
        print(f"Scan failed: {e}")

    # Test Patch
    print("\nTesting /api/patch...")
    patch_payload = {"code": "void func() { char buf[10]; strcpy(buf, input); }"}
    try:
        response = requests.post(f"{BASE_URL}/api/patch", json=patch_payload)
        print(f"Patch Response: {response.json()}")
    except Exception as e:
        print(f"Patch failed: {e}")

if __name__ == "__main__":
    test_api()
