import asyncio
import aiohttp
import base64


async def main():
    session = aiohttp.ClientSession()

    auth_value = "justasimplemail@mail.ru:pAsSWO_Rd1!!2"
    encoded_auth_value = base64.b64encode(auth_value.encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {encoded_auth_value}"}
    baseURL = "http://0.0.0.0:8000"
    json = {"email": "justasimplemail12@mail.ru", "password": "pAsSWO_R!+d1"}
    # json = {
    #     "title": "Charming 3-Bedroom Home in Prime Location",
    #     "description": "Nestled in a quiet, friendly neighborhood, this beautifully updated 3-bedroom, 2-bathroom home offers comfort and convenience. The spacious open-concept living area is perfect for entertaining, while the fully-equipped kitchen features modern appliances and ample counter space. Enjoy relaxing in the large backyard, ideal for family gatherings or outdoor activities. With a two-car garage, new flooring throughout, and easy access to shopping, dining, and top-rated schools, this home is perfect for families and professionals alike. Don't miss your chance to own this move-in-ready gem!"
    # }
    response = await session.post(f"{baseURL}/user", json=json, headers=headers)

    print(response.status)
    print(await response.text())
    await session.close()


asyncio.run(main())