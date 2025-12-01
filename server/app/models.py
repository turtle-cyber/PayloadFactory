from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class VulnerabilityReport(BaseModel):
    """
    MongoDB Schema for Vulnerability Reports.
    """
    file_name: str
    line_no: int
    detected_vuln_code_snippet: str
    cwe: str
    severity: str
    confidence: float
    owasp: str
    execution_time: float
    date_and_time: datetime = Field(default_factory=datetime.now)
    generated_exploit: Optional[str] = None
    payload: Optional[str] = None
    success: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "file_name": "vulnerable_app.py",
                "line_no": 42,
                "detected_vuln_code_snippet": "os.system(user_input)",
                "cwe": "CWE-78",
                "severity": "High",
                "confidence": 0.95,
                "owasp": "A03:2021-Injection",
                "execution_time": 0.45,
                "date_and_time": "2023-10-27T10:00:00",
                "generated_exploit": "import os; os.system('id')",
                "payload": "; id",
                "success": True
            }
        }
