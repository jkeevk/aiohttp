import os
import json
import base64
import hashlib
from pydantic import ValidationError

from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound, HTTPConflict
from models import init_orm, close_orm, Session, User, Advert

from sqlalchemy.orm import joinedload
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from schema import CreateUser, UpdateUser, CreateAdvert, UpdateAdvert


def validate(json_data, schema_cls):
    try:
        schema_obj = schema_cls(**json_data)
        return schema_obj.model_dump(exclude_unset=True)
    except ValidationError as err:
        raise HttpError(400, [error["msg"] for error in err.errors()])


async def auth_check(session: AsyncSession, auth_header):
    if not auth_header:
        raise HttpError(401, "Login or password not provided")

    auth_type, auth_value = auth_header.split(" ", 1)
    if auth_type.lower() != "basic":
        raise HttpError(401, "Invalid authorization type")

    decoded_auth_header = base64.b64decode(auth_value).decode("utf-8")
    email, password = decoded_auth_header.split(":", 1)

    result = await session.execute(select(User).filter(User.email == email))
    user = result.scalars().first()

    if not user or not verify_password(user.password, password):
        raise HttpError(401, "Invalid login or password")

    return user


class HttpError(Exception):
    def __init__(self, status_code: int, message: str | list):
        self.status_code = status_code
        self.message = message


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    password_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    return f"{salt.hex()}${password_hash}"


def verify_password(stored_hash: str, password: str) -> bool:
    salt, stored_password_hash = stored_hash.split("$")
    salt = bytes.fromhex(salt)
    return stored_password_hash == hashlib.sha256(salt + password.encode()).hexdigest()


def generate_error(error_cls, message):
    error = error_cls(
        text=json.dumps({"error": message}), content_type="application/json"
    )
    return error


async def get_user_by_id(session: AsyncSession, user_id: int) -> User:
    result = await session.execute(select(User).filter(User.id == user_id))
    user = result.scalars().one_or_none()
    if user is None:
        raise generate_error(HTTPNotFound, "User not found")
    return user


async def add_user(session: AsyncSession, user: User):
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        raise generate_error(HTTPConflict, "User already exists")


async def get_advert_by_id(session: AsyncSession, advert_id: int) -> Advert:
    result = await session.execute(
        select(Advert).options(joinedload(Advert.owner)).filter(Advert.id == advert_id)
    )
    advert = result.scalars().first()
    if advert is None:
        raise generate_error(HTTPNotFound, "Advert not found")
    return advert


async def add_advert(session: AsyncSession, advert: Advert):
    session.add(advert)
    try:
        await session.commit()
    except IntegrityError:
        raise generate_error(HTTPConflict, "User does not exist for this advert")


async def orm_context(app: web.Application):
    print("Initializong ORM")
    await init_orm()
    yield
    await close_orm()
    print("Closing ORM")


@web.middleware
async def session_middleware(request: web.Request, handler: web.RequestHandler):
    async with Session() as session:
        print("Before request")
        request.session = session
        result = await handler(request)
        print("After request")

        return result


class UserView(web.View):
    @property
    def user_id(self):
        return int(self.request.match_info["user_id"])

    async def get(self):
        user = await get_user_by_id(self.request.session, self.user_id)
        return web.json_response(user.dict)

    async def post(self):
        json_data = validate(await self.request.json(), CreateUser)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        await add_user(self.request.session, user)
        return web.json_response(user.id_dict)

    async def patch(self):
        user = await auth_check(
            self.request.session, self.request.headers.get("Authorization")
        )

        if self.user_id != user.id:
            raise HttpError(403, "Forbidden")

        json_data = validate(await self.request.json(), UpdateUser)

        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])

        for field, value in json_data.items():
            setattr(user, field, value)

        await add_user(self.request.session, user)
        return web.json_response(user.id_dict)

    async def delete(self):
        user = await auth_check(
            self.request.session, self.request.headers.get("Authorization")
        )

        if self.user_id != user.id:
            raise HttpError(403, "Forbidden")

        user = await get_user_by_id(self.request.session, self.user_id)
        await self.request.session.delete(user)
        await self.request.session.commit()
        return web.json_response({"status": "deleted"})


class AdvertView(web.View):
    @property
    def advert_id(self):
        return int(self.request.match_info["advert_id"])

    async def get(self):
        advert = await get_advert_by_id(self.request.session, self.advert_id)
        return web.json_response(advert.dict)

    async def post(self):
        user = await auth_check(
            self.request.session, self.request.headers.get("Authorization")
        )
        json_data = validate(await self.request.json(), CreateAdvert)
        json_data["owner_id"] = user.id

        advert = Advert(**json_data)
        await add_advert(self.request.session, advert)
        return web.json_response(advert.id_dict)

    async def patch(self):
        user = await auth_check(
            self.request.session, self.request.headers.get("Authorization")
        )
        json_data = validate(await self.request.json(), UpdateAdvert)
        advert = await get_advert_by_id(self.request.session, self.advert_id)

        if advert.owner_id != user.id:
            raise HttpError(403, "Forbidden")

        for field, value in json_data.items():
            setattr(advert, field, value)
        await add_advert(self.request.session, advert)
        return web.json_response(advert.id_dict)

    async def delete(self):
        user = await auth_check(
            self.request.session, self.request.headers.get("Authorization")
        )
        advert = await get_advert_by_id(self.request.session, self.advert_id)

        if advert.owner_id != user.id:
            raise HttpError(403, "Forbidden")

        await self.request.session.delete(advert)
        await self.request.session.commit()
        return web.json_response({"status": "deleted"})


app = web.Application()
app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)
app.add_routes(
    [
        web.get("/user/{user_id:[0-9]+}", UserView),
        web.patch("/user/{user_id:[0-9]+}", UserView),
        web.delete("/user/{user_id:[0-9]+}", UserView),
        web.post("/user", UserView),
        web.get("/advert/{advert_id:[0-9]+}", AdvertView),
        web.patch("/advert/{advert_id:[0-9]+}", AdvertView),
        web.delete("/advert/{advert_id:[0-9]+}", AdvertView),
        web.post("/advert", AdvertView),
    ]
)


if __name__ == "__main__":
    web.run_app(app)
