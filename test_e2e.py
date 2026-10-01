"""End-to-end integration and SRS compliance test suite for CyberLens AI."""
import io
import sys
from app import app

def run_tests():
    print("=" * 60)
    print(" Running CyberLens AI SRS Full Verification Test Suite")
    print("=" * 60)

    client = app.test_client()

    # 1. Home page (SRS §3.1a)
    res = client.get('/')
    assert res.status_code == 200, f'Home page failed: {res.status_code}'
    assert b'CyberLens AI' in res.data
    print("✓ 1. Home page (SRS §3.1a): OK")

    # 2. Authentication (SRS §3.1, NFR-4)
    res = client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'}, follow_redirects=True)
    assert b'Invalid' in res.data
    res = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    assert res.status_code == 200
    assert b'Upload' in res.data or b'Welcome' in res.data
    print("✓ 2. Authentication & Session Management: OK")

    # 3. Upload page GET (SRS §3.1b)
    res = client.get('/upload')
    assert res.status_code == 200
    assert b'Upload Dataset' in res.data
    print("✓ 3. Upload page GET (SRS §3.1b): OK")

    # 4. File Upload (FR-1, FR-3, FR-4)
    with open('data/sample_security_log.csv', 'rb') as f:
        res = client.post('/upload', data={'file': (io.BytesIO(f.read()), 'sample.csv')}, content_type='multipart/form-data')
    assert res.status_code == 200, f'Upload failed: {res.status_code} {res.data}'
    data = res.get_json()
    assert data.get('success') is True, f"Upload response error: {data}"
    print("✓ 4. File Upload & Validation (FR-1, FR-3, FR-4): OK")

    # 5. Dataset preview page (SRS §3.1c)
    res = client.get('/preview')
    assert res.status_code == 200
    assert b'Dataset Preview' in res.data
    assert b'Run AI Analysis' in res.data
    print("✓ 5. Dataset Preview Page (SRS §3.1c): OK")

    # 6. AI Analysis pipeline (FR-5 to FR-13)
    res = client.post('/analyze')
    assert res.status_code == 200, f'Analyze failed: {res.status_code} {res.data}'
    data = res.get_json()
    assert data.get('success') is True, f"Analyze response error: {data}"
    print("✓ 6. AI Analysis Pipeline (FR-5 to FR-13): OK")

    # 7. Dashboard (SRS §3.1d)
    res = client.get('/dashboard')
    assert res.status_code == 200
    assert b'Analysis Dashboard' in res.data
    assert b'Attack Category Breakdown' in res.data
    print("✓ 7. Dashboard & Stat Cards (SRS §3.1d): OK")

    # 8. Stats API for Chart.js (FR-12, FR-13)
    res = client.get('/api/stats')
    assert res.status_code == 200
    stats = res.get_json()
    assert 'total_records' in stats
    assert 'category_distribution' in stats
    assert 'severity_distribution' in stats
    print("✓ 8. Stats API for Chart.js Visualizations: OK")

    # 9. Incident Report view (SRS §3.1e, FR-14, FR-15)
    res = client.get('/report')
    assert res.status_code == 200
    assert b'Incident Report' in res.data
    assert b'Executive Summary' in res.data
    print("✓ 9. Incident Report Page & Timeline (SRS §3.1e, FR-14, FR-15): OK")

    # 10. PDF Export (FR-16)
    res = client.get('/download-report')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert len(res.data) > 1000
    print(f"✓ 10. PDF Export (FR-16): OK ({len(res.data):,} bytes)")

    # 11. Format verification: XLSX upload & analysis
    with open('data/sample_security_log.xlsx', 'rb') as f:
        res = client.post('/upload', data={'file': (io.BytesIO(f.read()), 'sample.xlsx')}, content_type='multipart/form-data')
    assert res.status_code == 200
    res = client.post('/analyze')
    assert res.status_code == 200
    print("✓ 11. Excel (.xlsx) End-to-End Pipeline (FR-1): OK")

    # 12. Format verification: Log file upload & analysis
    with open('data/sample_auth.log', 'rb') as f:
        res = client.post('/upload', data={'file': (io.BytesIO(f.read()), 'sample_auth.log')}, content_type='multipart/form-data')
    assert res.status_code == 200
    res = client.post('/analyze')
    assert res.status_code == 200
    print("✓ 12. Log file (.log) End-to-End Pipeline (FR-1, FR-5-8): OK")

    print("=" * 60)
    print(" ALL 12 SRS REQUIREMENTS VERIFIED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == '__main__':
    run_tests()
