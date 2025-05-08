from fastapi import APIRouter
from . import login,register,general

router = APIRouter()

router.include_router(general.router,prefix="",tags=["General"])
router.include_router(login.router,prefix="",tags=["Login"])
router.include_router(register.router,prefix="",tags=["Register"])

