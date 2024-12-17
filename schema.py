from pydantic import BaseModel, field_validator
import re


class BaseUser(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str):
        if "@" not in value:
            raise ValueError("Email must contain '@' symbol.")        
        
        domain = value.split('@')[1] if '@' in value else ''
        if '.' not in domain:
            raise ValueError("Email must contain a domain after '@' with a '.' in it.")

        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, value):
            raise ValueError("Invalid email format.")
        
        return value

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        if len(value) < 8:
            raise ValueError("Password is too short, it must be at least 8 characters.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit.")

        return value


class BaseAdvert(BaseModel):
    title: str
    description: str
    owner_id: int

    @field_validator("title")
    @classmethod
    def check_title(cls, value: str):
        if len(value) < 6:
            raise ValueError("Title is too short, it must be at least 6 characters.")
        return value

    @field_validator("description")
    @classmethod
    def check_description(cls, value: str):
        if len(value) < 10:
            raise ValueError(
                "Description is too short, it must be at least 10 characters."
            )
        return value


class CreateUser(BaseUser):
    email: str
    password: str


class UpdateUser(BaseUser):
    email: str = None
    password: str = None


class CreateAdvert(BaseAdvert):
    title: str
    description: str
    owner_id: int = None


class UpdateAdvert(BaseAdvert):
    title: str = None
    description: str = None
    owner_id: int = None

