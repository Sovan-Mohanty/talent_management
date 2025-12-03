from fastapi import APIRouter, File, UploadFile, Depends, Query,HTTPException
from typing import List, Optional
import PyPDF2
from docx import Document
from io import BytesIO
from database import collections
from models import Employee, UserRole
from utils.security import get_current_user
from datetime import datetime

router = APIRouter()

async def extract_text(file: UploadFile):
    content = await file.read()
    if file.filename.endswith(".pdf"):
        reader = PyPDF2.PdfReader(BytesIO(content))
        return " ".join(page.extract_text() or "" for page in reader.pages)
    elif file.filename.endswith((".doc", ".docx")):
        doc = Document(BytesIO(content))
        return " ".join(p.text for p in doc.paragraphs)
    return ""

@router.post("/resume")
async def upload_resume(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    print(current_user)
    if current_user["role"] not in [UserRole.EMPLOYEE_TP, UserRole.EMPLOYEE_NON_TP]:
        raise HTTPException(403)
    text = await extract_text(file)
    await collections["employees"].update_one(
        {"employee_id": int(current_user["employee_id"])},
        {"$set": {"resume_text": text, "updated_at": datetime.utcnow()}}
    )
    return {"message": "Resume uploaded and parsed"}

@router.get("/", response_model=List[Employee])
async def search_employees(
    type: Optional[str] = Query(None),
    skills: Optional[str] = Query(None),
    location: Optional[str] = Query(None),
    band: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    print(current_user)
    query = {}
    role = current_user["role"]

    if role == UserRole.TP_MANAGER:
        query["type"] = "TP"
    elif role == UserRole.WFM:
        # Show only applicants to their jobs
        job_rr_ids = [j["rr_id"] async for j in collections["jobs"].find({"wfm_id": current_user["employee_id"]}, {"rr_id": 1})]
        apps = await collections["applications"].find({"job_rr_id": {"$in": job_rr_ids}}).to_list(None)
        query["employee_id"] = {"$in": [a["employee_id"] for a in apps]}
    elif role == UserRole.HM:
        job_rr_ids = [j["rr_id"] async for j in collections["jobs"].find({"hm_id": current_user["employee_id"]}, {"rr_id": 1})]
        apps = await collections["applications"].find({"job_rr_id": {"$in": job_rr_ids}, "status": "Allocated"}).to_list(None)
        query["employee_id"] = {"$in": [a["employee_id"] for a in apps]}

    if type:
        query["type"] = type
    if skills:
        query["skills"] = {"$in": [s.strip() for s in skills.split(",")]}
    if location:
        query["city"] = {"$regex": location, "$options": "i"}
    if band:
        query["band"] = band

    employees = await collections["employees"].find(query).to_list(200)
    return [Employee(**e) for e in employees]