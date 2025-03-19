from flask import Flask, jsonify, request
from flask_cors import CORS
import mysql.connector
import os
from dotenv import load_dotenv
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from contextlib import contextmanager

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuración JWT
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "clave-secreta-temporal")
jwt = JWTManager(app)

# Gestor de conexión a la base de datos usando contextmanager
@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME")
        )
        yield conn
    finally:
        if conn is not None:
            conn.close()

# Ruta principal
@app.route('/')
def home():
    return {"mensaje": "Hola Mundo desde Flask API"}

# ===== RUTAS DE ADMINS =====

# Ruta para obtener los admins
@app.route('/admins', methods=['GET'])
def get_admins():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM admins")
    admins = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(admins)

# Crear un nuevo admin
@app.route('/admins', methods=['POST'])
@jwt_required()
def create_admin():
    try:
        data = request.json
        nombre = data.get("nombre")
        email = data.get("email")
        password = data.get("password")

        if not nombre or not email or not password:
            return jsonify({"error": "Todos los campos son obligatorios"}), 400

        # Encriptar la contraseña y convertirla a string
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO admins (nombre, email, password) VALUES (%s, %s, %s)", 
                              (nombre, email, hashed_password))
                conn.commit()
                return jsonify({"mensaje": "Admin creado correctamente", "id": cursor.lastrowid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Actualizar un admin
@app.route('/admins/<int:id>', methods=['PUT'])
@jwt_required()
def update_admin(id):
    try:
        data = request.json
        nombre = data.get("nombre")
        email = data.get("email")

        if not nombre or not email:
            return jsonify({"error": "Nombre y email son obligatorios"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar que el admin existe
                cursor.execute("SELECT id FROM admins WHERE id = %s", (id,))
                if not cursor.fetchone():
                    return jsonify({"error": "Admin no encontrado"}), 404
                
                cursor.execute("UPDATE admins SET nombre=%s, email=%s, updated_at=NOW() WHERE id=%s", 
                              (nombre, email, id))
                conn.commit()
                if cursor.rowcount == 0:
                    return jsonify({"error": "No se realizaron cambios"}), 400
                return jsonify({"mensaje": "Admin actualizado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Eliminar un admin
@app.route('/admins/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_admin(id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar que el admin existe
                cursor.execute("SELECT id FROM admins WHERE id = %s", (id,))
                if not cursor.fetchone():
                    return jsonify({"error": "Admin no encontrado"}), 404
                
                cursor.execute("DELETE FROM admins WHERE id=%s", (id,))
                conn.commit()
                if cursor.rowcount == 0:
                    return jsonify({"error": "No se pudo eliminar el admin"}), 400
                return jsonify({"mensaje": "Admin eliminado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Obtener detalle de un admin
@app.route('/admins/<int:id>', methods=['GET'])
@jwt_required()
def get_admin(id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id, nombre, email, created_at, updated_at FROM admins WHERE id = %s", (id,))
                admin = cursor.fetchone()
                if not admin:
                    return jsonify({"error": "Admin no encontrado"}), 404
                return jsonify(admin)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== RUTAS DE USUARIOS =====

# Obtener todos los usuarios
@app.route('/usuarios', methods=['GET'])
@jwt_required()
def get_usuarios():
    try:
        with get_db_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id_usuario, nombre, apm, app, email, fn, telefono, created_at, updated_at FROM usuarios")
                usuarios = cursor.fetchall()
                return jsonify(usuarios)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Crear un nuevo usuario
@app.route('/usuarios', methods=['POST'])
@jwt_required()
def create_usuario():
    try:
        data = request.json
        nombre = data.get("nombre")
        apm = data.get("apm")
        app = data.get("app")
        email = data.get("email")
        fn = data.get("fn")
        telefono = data.get("telefono")
        password = data.get("password")

        if not nombre or not email or not password:
            return jsonify({"error": "Nombre, email y password son obligatorios"}), 400

        # Encriptar la contraseña y convertirla a string
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO usuarios (nombre, apm, app, email, fn, telefono, password) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (nombre, apm, app, email, fn, telefono, hashed_password))
                conn.commit()
                return jsonify({"mensaje": "Usuario creado correctamente", "id": cursor.lastrowid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Actualizar un usuario
@app.route('/usuarios/<int:id>', methods=['PUT'])
@jwt_required()
def update_usuario(id):
    try:
        data = request.json
        nombre = data.get("nombre")
        apm = data.get("apm")
        app = data.get("app")
        email = data.get("email")
        telefono = data.get("telefono")

        if not nombre or not email:
            return jsonify({"error": "Nombre y email son obligatorios"}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar que el usuario existe
                cursor.execute("SELECT id_usuario FROM usuarios WHERE id_usuario = %s", (id,))
                if not cursor.fetchone():
                    return jsonify({"error": "Usuario no encontrado"}), 404
                
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=%s, apm=%s, app=%s, email=%s, telefono=%s, updated_at=NOW() 
                    WHERE id_usuario=%s
                """, (nombre, apm, app, email, telefono, id))
                conn.commit()
                if cursor.rowcount == 0:
                    return jsonify({"error": "No se realizaron cambios"}), 400
                return jsonify({"mensaje": "Usuario actualizado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Eliminar un usuario
@app.route('/usuarios/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_usuario(id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar que el usuario existe
                cursor.execute("SELECT id_usuario FROM usuarios WHERE id_usuario = %s", (id,))
                if not cursor.fetchone():
                    return jsonify({"error": "Usuario no encontrado"}), 404
                
                cursor.execute("DELETE FROM usuarios WHERE id_usuario=%s", (id,))
                conn.commit()
                if cursor.rowcount == 0:
                    return jsonify({"error": "No se pudo eliminar el usuario"}), 400
                return jsonify({"mensaje": "Usuario eliminado correctamente"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Obtener detalle de un usuario
@app.route('/usuarios/<int:id>', methods=['GET'])
@jwt_required()
def get_usuario(id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("""
                    SELECT id_usuario, nombre, apm, app, email, fn, telefono, created_at, updated_at 
                    FROM usuarios WHERE id_usuario = %s
                """, (id,))
                usuario = cursor.fetchone()
                if not usuario:
                    return jsonify({"error": "Usuario no encontrado"}), 404
                return jsonify(usuario)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Iniciar sesión de admin
@app.route('/admins/login', methods=['POST'])
def login_admin():
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Solicitud inválida, se esperaba un JSON"}), 400

        if not data.get('email') or not data.get('password'):
            return jsonify({"error": "Correo y contraseña son requeridos"}), 400

        email = data['email']
        password = data['password']

        with get_db_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id, email, password, nombre FROM admins WHERE email = %s", (email,))
                admin = cursor.fetchone()
                
                if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
                    admin_data = {"id": admin["id"], "email": admin["email"], "nombre": admin["nombre"]}
                    access_token = create_access_token(identity=admin['id'])
                    return jsonify({
                        "mensaje": "Inicio de sesión exitoso", 
                        "admin": admin_data, 
                        "token": access_token
                    }), 200
                else:
                    return jsonify({"error": "Credenciales incorrectas"}), 401
    except Exception as e:
        print(f"Error en login: {str(e)}")
        return jsonify({"error": "Error en el servidor"}), 500

# Iniciar sesión de usuario
@app.route('/usuarios/login', methods=['POST'])
def login_usuario():
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Solicitud inválida, se esperaba un JSON"}), 400

        if not data.get('email') or not data.get('password'):
            return jsonify({"error": "Correo y contraseña son requeridos"}), 400

        email = data['email']
        password = data['password']

        with get_db_connection() as conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT id_usuario, email, password, nombre FROM usuarios WHERE email = %s", (email,))
                usuario = cursor.fetchone()
                
                if usuario and bcrypt.checkpw(password.encode('utf-8'), usuario['password'].encode('utf-8')):
                    usuario_data = {"id": usuario["id_usuario"], "email": usuario["email"], "nombre": usuario["nombre"]}
                    access_token = create_access_token(identity=usuario['id_usuario'])
                    return jsonify({
                        "mensaje": "Inicio de sesión exitoso", 
                        "usuario": usuario_data, 
                        "token": access_token
                    }), 200
                else:
                    return jsonify({"error": "Credenciales incorrectas"}), 401
    except Exception as e:
        print(f"Error en login: {str(e)}")
        return jsonify({"error": "Error en el servidor"}), 500

# Verificar token (ruta protegida de ejemplo)
@app.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    current_user_id = get_jwt_identity()
    return jsonify({"mensaje": "Token válido", "usuario_id": current_user_id}), 200

if __name__ == '__main__':
    app.run(debug=True)