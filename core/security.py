from jose import JWTError, jwt
import datetime
from fastapi import HTTPException
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# Función para crear el token
def create_jwt_token(user_id: int):
    payload = {
        'user_id': user_id,  # ID del usuario
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)  # Expiración del token
    }
    # Codificar el payload y devolver el token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

# Función para decodificar el token y obtener el payload
def decode_jwt_token(token: str):
    try:
        # Decodificar el token y obtener el payload
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
