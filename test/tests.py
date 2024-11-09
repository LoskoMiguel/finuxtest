import os
import random
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import psycopg2
import bcrypt
from jose import JWTError, jwt
import datetime

load_dotenv()

app = FastAPI()

# Clave secreta para firmar el token
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# Conexión a la base de datos de Supabase
def get_db_connection():
    return psycopg2.connect(os.getenv("SUPABASE_DATABASE_URL"))

class User(BaseModel):
    fullname: str
    email: str
    dni: str
    password: str
    confirm_password: str

class UserResponse(BaseModel):
    id: int
    status: str
    numero_cuenta: str

# funcion para crear el token
def create_jwt_token(user_id: int):
    payload = {
        'user_id': user_id, # ID del usuario sacado de la base de datos
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)  # Expiración del token
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    print(token)
    return token

create_jwt_token(1)
# funcion para decodificar el token y obtener el payload
#el payload es el contenido del token
def decode_jwt_token(token: str):
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

@app.post("/register", response_model=UserResponse)
async def register_user(user: User):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden.")
    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    connection = get_db_connection()
    cursor = connection.cursor()

    # Verificar si el correo ya existe
    cursor.execute("SELECT id FROM usuarios WHERE email = %s", (user.email,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    # Verificar si el DNI ya existe
    cursor.execute("SELECT id FROM usuarios WHERE dni = %s", (user.dni,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="El DNI ya está registrado.")

    # Generar número de cuenta con serie fija y dígitos aleatorios
    serie_fija = "123"  # Serie fija de 3 dígitos
    while True:
        digitos_aleatorios = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # 6 dígitos aleatorios
        numero_cuenta = serie_fija + digitos_aleatorios
        cursor.execute("SELECT id FROM usuarios WHERE numero_cuenta = %s", (numero_cuenta,))
        if not cursor.fetchone():
            break

    insert_sql = """
    INSERT INTO usuarios (full_name, email, password, dni, numero_cuenta) VALUES (%s, %s, %s, %s, %s)
    RETURNING id;
    """
    
    try:
        cursor.execute(insert_sql, (user.fullname, user.email, hashed_password, user.dni, numero_cuenta)) 
        user_id = cursor.fetchone()[0]
        connection.commit()
        token = create_jwt_token(user_id)
        return {"id": user_id, "status": "Usuario registrado exitosamente", "numero_cuenta": numero_cuenta, "token": token}
    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        connection.close()