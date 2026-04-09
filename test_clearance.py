from app import app
from flask import render_template

app.config['WTF_CSRF_ENABLED'] = False

with app.app_context():
    client = app.test_client()
    try:
        resp = client.get('/admin/dashboard')
        print("Dashboard status:", resp.status_code)
        if resp.status_code == 500:
            print(resp.data)
    except Exception as e:
        import traceback
        traceback.print_exc()
