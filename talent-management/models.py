from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum
import uuid

class ForgotPasswordRequest(BaseModel):
    email:str

class verifyCodeRequest(BaseModel):
    email:str
    code:str

class ResetPasswordRequest(BaseModel):
    email:str
    code:str
    new_password:str
class UserRole(str, Enum):
    ADMIN = "Admin"
    TP_MANAGER = "TP Manager"
    WFM = "WFM"
    HM = "HM"
    EMPLOYEE_TP = "TP"
    EMPLOYEE_NON_TP = "Non TP"

class ApplicationStatus(str, Enum):
    DRAFT = "Draft"
    SUBMITTED = "Submitted"
    SHORTLISTED = "Shortlisted"
    INTERVIEW = "Interview"
    SELECTED = "Selected"
    REJECTED = "Rejected"
    ALLOCATED = "Allocated"
    WITHDRAWN = "Withdrawn"

class Employee(BaseModel):
    employee_id: int
    name: str
    designation: str
    band: str
    city: str
    location: str
    primary_technology: str
    secondary_technology: str
    skills: List[str] = []
    type: str  # "TP" or "Non TP"
    resume_text: Optional[str] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class Job(BaseModel):
    rr_id: str = Field(..., alias="_id")
    title: str
    location: str
    required_skills: List[str] = []
    description: str
    start_date: datetime
    end_date: datetime
    wfm_id: str
    hm_id: str
    status: str = "Open"
    job_grade: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Application(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    employee_id: int
    job_rr_id: str
    status: ApplicationStatus = ApplicationStatus.DRAFT
    resume: Optional[str] = None
    cover_letter: Optional[str] = None
    submitted_at: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True