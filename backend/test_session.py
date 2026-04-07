import requests

s = requests.Session()
# Simulate a mock login that doesn't actually hit google but hits our route
r0 = s.get('http://localhost:5000/')
r1 = s.post('http://localhost:5000/signin', json={'email': 'test@example.com', 'password': 'test'})
print("r1 cookies after POST signin:", s.cookies.get_dict())
r2 = s.get('http://localhost:5000/dashboard')
print("r2 text length (should be dashboard HTML if success):", len(r2.text))
if 'dashboard' in r2.text.lower():
    print("Email sign-in works")

# Now let's test social login
# Wait, social login redirects through oauth, we can't easily mock it.
# We can just check the cookie headers from our signin endpoint
