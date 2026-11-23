import json
from fastapi.testclient import TestClient
from deploy.app import app, PublicRequestGuard, REQUESTS_PER_MINUTE
import analyzer

with TestClient(app) as client:
    assert not analyzer.USE_FEEDBACK
    assert client.get('/health').json() == {'status': 'ok'}
    assert client.get('/demo-config').json() == {'feedbackEnabled': False}
    assert client.get('/dashboard').status_code == 200
    for method, target in [('GET','/feedback'),('POST','/feedback'),('DELETE','/feedback/1')]:
        assert client.request(method,target).status_code == 404
    for url in ['', 'ftp://example.com', 'https://u:p@example.com', 'https://'+'a'*2050]:
        assert client.post('/analyze',json={'url':url}).status_code == 422, url[:40]
    assert client.post('/analyze', content=b'x'*17000).status_code == 413
    result=client.post('/analyze',json={'url':'https://example.com'})
    assert result.status_code == 200, result.text
    body=result.json()
    assert body['prediction'] in ['benign','malware','phishing']
    assert body['feedback'] is None
    assert all(key in body for key in ['trace','drivers','reasons','layers'])
    print(json.dumps({'prediction':body['prediction'],'elapsed_ms':body['elapsed_ms'],'feedback':body['feedback']}))
limiter=PublicRequestGuard(None)
assert all(limiter._allow(1000) for _ in range(REQUESTS_PER_MINUTE))
assert not limiter._allow(1000)
assert limiter._allow(1060)
print('Real-model public gateway: readiness, routes, feedback isolation, validation, body cap, analysis and shared rate limiter pass.')
