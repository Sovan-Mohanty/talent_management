from fastapi import APIRouter, Depends, HTTPException
from database import collections
from models import ApplicationStatus, UserRole
from utils.security import get_current_user

router = APIRouter()

async def get_manager_applications(current_user: dict, status_filter: list = None):
    role = current_user["role"]
    emp_id = current_user["employee_id"]

    query = {}

    if role == "TP Manager":
        tp_emp_ids = [e["employee_id"] async for e in collections["employees"].find({"type": "TP"}, {"employee_id": 1})]
        query = {"employee_id": {"$in": tp_emp_ids}, "status": "Submitted"}

    elif role == "WFM":
        job_rr_ids = [j["_id"] async for j in collections["jobs"].find({"wfm_id": emp_id}, {"_id": 1})]
        query = {"job_rr_id": {"$in": job_rr_ids}}
        if status_filter:
            query["status"] = {"$in": status_filter}

    elif role == "HM":
        job_rr_ids = [j["_id"] async for j in collections["jobs"].find({"hm_id": emp_id}, {"_id": 1})]
        query = {"job_rr_id": {"$in": job_rr_ids}, "status": "Selected"}

    else:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return await collections["applications"].find(query).to_list(200)

@router.get("/applications")
async def list_applications(current_user: dict = Depends(get_current_user)):
    apps = await get_manager_applications(current_user)
    return apps

@router.put("/applications/{app_id}/shortlist")
async def shortlist(app_id: str, current_user: dict = Depends(get_current_user)):
    app = await collections["applications"].find_one({"_id": app_id})
    emp = await collections["employees"].find_one({"employee_id": app["employee_id"]})
    if current_user["role"] == UserRole.TP_MANAGER and emp["type"] == "TP" and app["status"] == ApplicationStatus.SUBMITTED:
        await collections["applications"].update_one({"_id": app_id}, {"$set": {"status": ApplicationStatus.SHORTLISTED}})
        return {"message": "Shortlisted by TP Manager"}
    if current_user["role"] == UserRole.WFM and emp["type"] == "Non TP" and app["status"] == ApplicationStatus.SUBMITTED:
        await collections["applications"].update_one({"_id": app_id}, {"$set": {"status": ApplicationStatus.SHORTLISTED}})
        return {"message": "Shortlisted by WFM"}
    raise HTTPException(403)

@router.put("/applications/{app_id}/interview")
async def to_interview(app_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.WFM:
        raise HTTPException(403)
    await collections["applications"].update_one(
        {"_id": app_id, "status": ApplicationStatus.SHORTLISTED},
        {"$set": {"status": ApplicationStatus.INTERVIEW}}
    )
    return {"message": "Moved to Interview"}

@router.put("/applications/{app_id}/select")
async def select_candidate(app_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.WFM:
        raise HTTPException(403)
    await collections["applications"].update_one(
        {"_id": app_id, "status": ApplicationStatus.INTERVIEW},
        {"$set": {"status": ApplicationStatus.SELECTED}}
    )
    return {"message": "Selected"}

@router.put("/applications/{app_id}/reject")
async def reject_candidate(app_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.WFM:
        raise HTTPException(403)
    await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {"status": ApplicationStatus.REJECTED}}
    )
    return {"message": "Rejected"}

@router.put("/applications/{app_id}/allocate")
async def allocate(app_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != UserRole.HM:
        raise HTTPException(403)
    app = await collections["applications"].find_one({"_id": app_id, "status": ApplicationStatus.SELECTED})
    job = await collections["jobs"].find_one({"rr_id": app["job_rr_id"], "hm_id": current_user["employee_id"]})
    if not job:
        raise HTTPException(403)
    await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {"status": ApplicationStatus.ALLOCATED}}
    )
    return {"message": "Allocated Successfully"}