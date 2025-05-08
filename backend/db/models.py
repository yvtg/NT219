from pydantic import BaseModel
from sqlalchemy import JSON ,Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from db.schemas import *

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # user hoặc admin
    household = Column(JSON, default={"ip_address": "", "devices": []})
    plan = Column(String, default="basic")  # basic, standard, premium
