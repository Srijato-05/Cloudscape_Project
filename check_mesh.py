import socket
import azure.storage.blob

def test_port(name, ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        status = "ONLINE" if result == 0 else "OFFLINE"
        print(f"{name} ({ip}:{port}): {status}")

print("Azure Storage SDK: INSTALLED")
test_port("LocalStack", "127.0.0.1", 4566)
test_port("Azurite", "127.0.0.1", 10000)
test_port("Neo4j", "127.0.0.1", 7687)
test_port("Redis", "127.0.0.1", 6379)