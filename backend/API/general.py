from fastapi import APIRouter

router=APIRouter()

@router.get("/")
def get_root():
    return {"Chào mừng bạn đến với đồ án NT219 "}