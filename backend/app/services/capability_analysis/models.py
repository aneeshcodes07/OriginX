from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class CapabilityCategory(str, Enum):
    FILESYSTEM_READ = "FILESYSTEM_READ"
    FILESYSTEM_WRITE = "FILESYSTEM_WRITE"
    NETWORK_OUTBOUND = "NETWORK_OUTBOUND"
    NETWORK_LISTEN = "NETWORK_LISTEN"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    ENVIRONMENT_ACCESS = "ENVIRONMENT_ACCESS"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DYNAMIC_CODE_EXECUTION = "DYNAMIC_CODE_EXECUTION"
    INSTALL_TIME_EXECUTION = "INSTALL_TIME_EXECUTION"
    BINARY_EXECUTION = "BINARY_EXECUTION"

class CapabilityFinding(BaseModel):
    capability_id: str
    capability_name: str
    category: CapabilityCategory
    file_path: str
    line_number: int = 1
    evidence_excerpt: str
    detection_method: str = "static_analysis"  # python_ast, js_ast_token, metadata_inspection, binary_inspection
    confidence: str = "HIGH"  # LOW, MEDIUM, HIGH
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "capability_name": self.capability_name,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence_excerpt": self.evidence_excerpt,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "explanation": self.explanation
        }
