from pydantic import BaseModel
from typing import Optional

class HealthResponse(BaseModel):
    status: str
    version: str
    project_name: str
    environment: str
    database_connected: bool
    redis_status: str = "operational"
    model_registry_status: str = "healthy"
    api_status: str = "healthy"
