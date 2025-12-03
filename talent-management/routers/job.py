from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Optional
from database import collections
from models import Job, UserRole
from utils.security import get_current_user

router = APIRouter()

@router.get("/", response_model=List[Job])
async def get_jobs(
    location: Optional[str] = Query(None),
    grade: Optional[str] = Query(None),
    skills: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    query = {"status": "Open"}

    # Role-based filtering
    if current_user["role"] == UserRole.WFM:
        query["wfm_id"] = current_user["employee_id"]
    elif current_user["role"] == UserRole.HM:
        query["hm_id"] = current_user["employee_id"]
    elif current_user["role"] in [UserRole.EMPLOYEE_TP, UserRole.EMPLOYEE_NON_TP]:
        employee = await collections["employees"].find_one({"employee_id": int(current_user["employee_id"])})
        if employee["type"] == "TP":
            band_num = int(employee["band"][1:]) if employee["band"].startswith("B") else 0
            allowed = [f"B{band_num-1}", f"B{band_num}", f"B{band_num+1}"]
            query["job_grade"] = {"$in": allowed}

    if location:
        query["location"] = {"$regex": location, "$options": "i"}
    if grade:
        query["job_grade"] = grade
    if skills:
        query["required_skills"] = {"$in": [s.strip() for s in skills.split(",")]}

    jobs = await collections["jobs"].find(query).to_list(100)
    return [Job(**j) for j in jobs]

@router.post("/")
async def create_job(job: Job, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.HM:
        raise HTTPException(403, "Only Hiring Manager can create jobs")
    job_dict = job.dict(by_alias=True)
    await collections["jobs"].insert_one(job_dict)
    return job_dict