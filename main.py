from client import DeterministicApiClient

if __name__ == "__main__":
    client = DeterministicApiClient("https://httpbin.org", timeout_seconds=5)
    response = client.request("GET", "/status/200")
    print("Status:", response.status_code)
