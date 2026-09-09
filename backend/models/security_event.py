from datetime import datetime as DateTime
from typing import Literal, Optional

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    id: int
    timestamp: DateTime
    event_type: str
    source: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str