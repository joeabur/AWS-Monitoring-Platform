import json
import sys

from app.core.config import get_settings
from app.database import get_session_factory
from app.notifications.service import dispatch_due_notifications


def main() -> int:
    session = get_session_factory()()
    try:
        result = dispatch_due_notifications(session, get_settings())
    finally:
        session.close()
    print(json.dumps(result, sort_keys=True))
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
