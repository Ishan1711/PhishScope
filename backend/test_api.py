import unittest
import json
import io
from app import create_app

class TestPhishScopeAPI(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_health(self):
        response = self.client.get('/api/v1/health')
        self.assertEqual(response.status_code, 200)

    def test_analyze_text(self):
        sample_text = "From: attacker@evil.com\nTo: victim@company.com\nSubject: Urgent\nAuthentication-Results: spf=fail"
        response = self.client.post('/api/v1/analyze/text', json={"text": sample_text})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("investigation_id", data)
        self.assertEqual(data["header_data"]["from_address"], "attacker@evil.com")
        self.assertEqual(data["risk_assessment"]["threat_level"], "SUSPICIOUS")

    def test_analyze_file(self):
        sample_text = b"From: attacker@evil.com\nTo: victim@company.com\nSubject: Urgent\nAuthentication-Results: spf=fail"
        data = {
            'file': (io.BytesIO(sample_text), 'test.txt')
        }
        response = self.client.post('/api/v1/analyze/file', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertEqual(json_data["header_data"]["from_address"], "attacker@evil.com")

if __name__ == '__main__':
    unittest.main()
