from app import app

with app.test_client() as client:
    response = client.get('/')
    print(f"Status: {response.status_code}")
    print(f"Content length: {len(response.data)}")
    if b'<html' in response.data:
        print("HTML received successfully")
    else:
        print("HTML not found in response")
        print(response.data[:500])