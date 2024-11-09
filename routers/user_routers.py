from fastapi import APIRouter, HTTPException, Header
from models.user import User, Login, Transferencias
from db.connection import get_db_connection
from core.security import create_jwt_token, decode_jwt_token
import bcrypt
import random

router = APIRouter()

# Ruta para registrar usuarios
@router.post("/register")
async def register_user(user: User):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden.")
    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT email FROM usuarios WHERE email = %s", (user.email,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")

    cursor.execute("SELECT dni FROM usuarios WHERE dni = %s", (user.dni,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="El DNI ya está registrado.")

    serie_fija = "009"  # Serie fija de 3 dígitos
    digitos_aleatorios = ''.join([str(random.randint(0, 9)) for _ in range(6)])  # 6 dígitos aleatorios
    numero_cuenta = serie_fija + digitos_aleatorios

    cursor.execute("SELECT numero_cuenta FROM usuarios WHERE numero_cuenta = %s", (numero_cuenta,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="El número de cuenta ya está registrado.")

    insert_sql = """
    INSERT INTO usuarios (full_name, email, password, dni, numero_cuenta, rol, is_actived, cantidad_dinero) 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
    """
    
    try:
        cursor.execute(insert_sql, (user.fullname, user.email, hashed_password.decode('utf-8'), user.dni, numero_cuenta, "usuario", True, 0,))
        user_id = cursor.fetchone()[0]
        connection.commit()
        return {"id": user_id, "status": "Usuario registrado exitosamente", "numero_cuenta": numero_cuenta}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cursor.close()
        connection.close()

# Ruta para iniciar sesión y devolver un JWT
@router.post("/login")
async def login_user(login: Login):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id, password FROM usuarios WHERE dni = %s", (login.dni,))
    user_data = cursor.fetchone()

    if not user_data:
        raise HTTPException(status_code=400, detail="DNI o contraseña incorrectos.")

    user_id, stored_hashed_password = user_data

    if not bcrypt.checkpw(login.password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="DNI o contraseña incorrectos.")

    # Generar el token JWT
    token = create_jwt_token(user_id)

    return {"msg": "Login exitoso", "token": token}

# Ruta para transferencias, protegida con JWT
@router.post("/transferencias")
async def transfer_funds(transferencias: Transferencias, authorization: str = Header(None)):
    # Validar el token
    if not authorization:
        raise HTTPException(status_code=401, detail="Token no proporcionado.")
    
    # Extraer el token del encabezado
    token = authorization.split(" ")[1]  # Asumiendo que el formato es "Bearer TU_TOKEN"

    connection = get_db_connection()
    cursor = connection.cursor()
    
    try:
        # Verificar la cuenta que envía los fondos
        cursor.execute("SELECT id, numero_cuenta, cantidad_dinero, is_actived FROM usuarios WHERE numero_cuenta = %s", (transferencias.numero_cuenta_enviar,))
        user_data = cursor.fetchone()

        if not user_data:
            raise HTTPException(status_code=400, detail="Número de cuenta del remitente incorrecto.")

        user_id, user_numero_cuenta, user_cantidad_dinero, user_is_actived = user_data

        if not user_is_actived:
            raise HTTPException(status_code=400, detail="La cuenta del remitente no está activa.")

        if user_cantidad_dinero < transferencias.cantidad_dinero:
            raise HTTPException(status_code=400, detail="Fondos insuficientes en la cuenta del remitente.")

        # Verificar la cuenta que recibe los fondos
        cursor.execute("SELECT id, numero_cuenta, is_actived FROM usuarios WHERE numero_cuenta = %s", (transferencias.numero_cuenta_recibe,))
        recibir_data = cursor.fetchone()

        if not recibir_data:
            raise HTTPException(status_code=400, detail="Número de cuenta del destinatario incorrecto.")

        recibir_id, recibir_numero_cuenta, recibir_is_actived = recibir_data

        if not recibir_is_actived:
            raise HTTPException(status_code=400, detail="La cuenta del destinatario no está activa.")

        if transferencias.numero_cuenta_enviar == transferencias.numero_cuenta_recibe:
            raise HTTPException(status_code=400, detail="No puedes transferir fondos a la misma cuenta.")

        # Actualizar los saldos de ambas cuentas
        cursor.execute("UPDATE usuarios SET cantidad_dinero = cantidad_dinero - %s WHERE numero_cuenta = %s", (transferencias.cantidad_dinero, transferencias.numero_cuenta_enviar,))
        cursor.execute("UPDATE usuarios SET cantidad_dinero = cantidad_dinero + %s WHERE numero_cuenta = %s", (transferencias.cantidad_dinero, transferencias.numero_cuenta_recibe,))
        connection.commit()

        return {"status": "Transferencia exitosa", "numero_cuenta_enviar": transferencias.numero_cuenta_enviar, "numero_cuenta_recibe": transferencias.numero_cuenta_recibe}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        connection.close()
