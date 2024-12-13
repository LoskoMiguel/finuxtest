from fastapi import APIRouter, HTTPException, Header, Depends
from models.user import User, Login, Transferencias, Historial
from db.connection import get_db_connection
from core.security import create_jwt_token, decode_jwt_token
import bcrypt
import random
from datetime import datetime

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

    try:
        # Consulta combinada para obtener dni, password y rol en una sola consulta
        cursor.execute("SELECT id, password, rol FROM usuarios WHERE dni = %s", (login.dni,))
        user_data = cursor.fetchone()

        if not user_data:
            raise HTTPException(status_code=400, detail="DNI o contraseña incorrectos.")

        user_id, stored_hashed_password, user_rol = user_data

        if not bcrypt.checkpw(login.password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            raise HTTPException(status_code=400, detail="DNI o contraseña incorrectos.")

        # Generar el token JWT
        token = create_jwt_token(user_id)

        # Mapeo de roles más extensible
        valid_roles = {
            "admin": "admin",
            "usuario": "usuario", 
            "superusuario": "superusuario"
        }

        # Validar que el rol sea uno de los roles esperados
        if user_rol not in valid_roles:
            raise HTTPException(status_code=403, detail="Rol de usuario no válido")

        return {
            "msg": "Login exitoso", 
            "token": token, 
            "rol": valid_roles[user_rol]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el inicio de sesión: {str(e)}")
    finally:
        cursor.close()
        connection.close()

def get_current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token no proporcionado.")
    
    token = authorization.split(" ")[1]  # Formato "Bearer <token>"
    user_data = decode_jwt_token(token)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")
    
    return user_data  # Retorna el diccionario con datos del usuario, incluyendo el dni

@router.post("/transferencias")
async def transfer_funds(data: Transferencias, authorization: str = Header(None), current_user: dict = Depends(get_current_user)):
    # Extraer la información del usuario autenticado (dni)
    user_dni = current_user["dni"]
    user_numero_cuenta = current_user["numero_cuenta"]
    
    if data.numero_cuenta_enviar != user_numero_cuenta:
        raise HTTPException(status_code=400, detail="No puedes realizar transferencias desde una cuenta que no es tuya.")
    
    # Conexión a la base de datos
    connection = get_db_connection()
    cursor = connection.cursor()
    
    try:
        # Verificar la cuenta que envía los fondos
        cursor.execute("SELECT id, numero_cuenta, cantidad_dinero, is_actived FROM usuarios WHERE numero_cuenta = %s", (data.numero_cuenta_enviar,))
        user_data = cursor.fetchone()

        if not user_data:
            raise HTTPException(status_code=400, detail="Número de cuenta del remitente incorrecto.")
        
        user_id, user_numero_cuenta, user_cantidad_dinero, user_is_actived = user_data

        if not user_is_actived:
            raise HTTPException(status_code=400, detail="La cuenta del remitente no está activa.")

        if user_cantidad_dinero < data.cantidad_dinero:
            raise HTTPException(status_code=400, detail="Fondos insuficientes en la cuenta del remitente.")

        # Verificar la cuenta que recibe los fondos
        cursor.execute("SELECT id, numero_cuenta, is_actived FROM usuarios WHERE numero_cuenta = %s", (data.numero_cuenta_recibe,))
        recibir_data = cursor.fetchone()

        if not recibir_data:
            raise HTTPException(status_code=400, detail="Número de cuenta del destinatario incorrecto.")

        recibir_id, recibir_numero_cuenta, recibir_is_actived = recibir_data

        if not recibir_is_actived:
            raise HTTPException(status_code=400, detail="La cuenta del destinatario no está activa.")

        if data.numero_cuenta_enviar == data.numero_cuenta_recibe:
            raise HTTPException(status_code=400, detail="No puedes transferir fondos a la misma cuenta.")
        
        if data.cantidad_dinero <= 0:
            raise HTTPException(status_code=400, detail="No puedes transferir una cantidad de dinero igual o menor a 0")

        # Actualizar los saldos de ambas cuentas
        cursor.execute("UPDATE usuarios SET cantidad_dinero = cantidad_dinero - %s WHERE numero_cuenta = %s", (data.cantidad_dinero, data.numero_cuenta_enviar,))
        cursor.execute("UPDATE usuarios SET cantidad_dinero = cantidad_dinero + %s WHERE numero_cuenta = %s", (data.cantidad_dinero, data.numero_cuenta_recibe,))
        now = datetime.now()

        # Guardar fecha y hora en una sola variable
        fecha_y_hora = now.strftime("%Y-%m-%d %H:%M:%S") # Formato: YYYY-MM-DD HH:MM:SS
        cursor.execute("INSERT INTO historial (user_id, cuenta_usuario, cuenta_receptor, cantidad_dinero_enviada, fecha_enviado) VALUES (%s, %s, %s, %s, %s)", (user_id, data.numero_cuenta_enviar, data.numero_cuenta_recibe, data.cantidad_dinero, fecha_y_hora,))
        connection.commit()

        return {"status": "Transferencia exitosa", "numero_cuenta_enviar": data.numero_cuenta_enviar, "numero_cuenta_recibe": data.numero_cuenta_recibe}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        connection.close()

@router.post("/historial")
async def check_history(data: Historial, authorization: str = Header(None), current_user: dict = Depends(get_current_user)):
    # Extraer la información del usuario autenticado (dni)
    user_dni = current_user["dni"]
    user_numero_cuenta = current_user["numero_cuenta"]
    
    if data.numero_cuenta != user_numero_cuenta:
        raise HTTPException(status_code=400, detail="No Revisar El Historial De Otra Persona")
    
    # Conexión a la base de datos
    connection = get_db_connection()
    cursor = connection.cursor()
    
    try:
        # Verificar la cuenta que envía los fondos
        cursor.execute("SELECT numero_cuenta, is_actived FROM usuarios WHERE numero_cuenta = %s", (data.numero_cuenta,))
        user_data = cursor.fetchone()

        if not user_data:
            raise HTTPException(status_code=400, detail="Número de cuenta No Encontrado.")
        
        user_numero_cuenta, user_is_actived = user_data

        if not user_is_actived:
            raise HTTPException(status_code=400, detail="La cuenta Esta Desactivada")
        
        # Verificar la cuenta que envía los fondos
        cursor.execute("SELECT cuenta_usuario, cuenta_receptor, cantidad_dinero_enviada, fecha_enviado FROM historial WHERE cuenta_usuario = %s", (data.numero_cuenta,))
        history_data = cursor.fetchall()  # Cambiar fetchone a fetchall

        if not history_data:
            raise HTTPException(status_code=404, detail="No se encontró historial para esta cuenta.")

        # Crear una lista de resultados
        result = []
        for record in history_data:
            cuenta_usuario, cuenta_receptor, cantidad_dinero_enviada, fecha_enviado = record
            result.append({
                "Tu Cuenta": cuenta_usuario,
                "Numero De Cuenta Receptor": cuenta_receptor,
                "Cantidad De Dinero Enviada": cantidad_dinero_enviada,
                "Fecha Envio": fecha_enviado
            })

        return {"status": "Historiales Encontrados", "historial": result}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        connection.close()