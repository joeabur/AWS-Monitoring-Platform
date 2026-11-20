from datetime import datetime

from sqlalchemy import DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.models.user import Base


class AuditExportState(Base):
    __tablename__ = "audit_export_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_exported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
