from app import app
from models import db, IPBlacklist

with app.app_context():
    try:
        IPBlacklist.query.delete()
        db.session.commit()
        print("Cleared IP Blacklist.")
    except Exception as e:
        import traceback
        traceback.print_exc()
