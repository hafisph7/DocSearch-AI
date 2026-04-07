import requests

s = requests.Session()
r1 = s.get('http://localhost:5000/google_login', allow_redirects=False)
r2 = s.get('http://localhost:5000' + r1.headers['Location'], allow_redirects=False)
with open('test_out2.txt', 'w', encoding='utf-8') as f:
    f.write(f"r2 status: {r2.status_code}\n")
    f.write(f"r2 headers: {dict(r2.headers)}\n")
    f.write(f"r2 cookies: {s.cookies.get_dict()}\n")
