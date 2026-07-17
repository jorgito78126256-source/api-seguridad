const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const morgan = require("morgan");
const helmet = require("helmet");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());
app.use(helmet());
app.use(morgan("combined"));

// Registro de actividades
app.use((req, res, next) => {
    const fecha = new Date().toISOString();

    console.log(
        `[ACTIVIDAD] Fecha: ${fecha} | Metodo: ${req.method} | Ruta: ${req.originalUrl}`
    );

    next();
});

// Usuarios para iniciar sesion
const usuariosRegistrados = [
    {
        id: 1,
        username: "admin",
        password: "1234",
        role: "admin"
    },
    {
        id: 2,
        username: "jorge",
        password: "5678",
        role: "user"
    }
];

// Lista de usuarios
let users = [
    {
        id: 1,
        nombre: "Jorge Michell",
        correo: "jorge@correo.com"
    }
];

// Ruta principal
app.get("/", (req, res) => {
    res.json({
        mensaje: "API segura funcionando correctamente",
        seguridad: "JWT y autorizacion por roles",
        estado: "Activa"
    });
});

// Mostrar usuarios
app.get("/users", (req, res) => {
    res.json(users);
});

// Agregar usuario
app.post("/users", (req, res) => {
    const { nombre, correo } = req.body;

    if (!nombre || !correo) {
        return res.status(400).json({
            mensaje: "El nombre y el correo son obligatorios"
        });
    }

    const nuevoUsuario = {
        id: users.length + 1,
        nombre,
        correo
    };

    users.push(nuevoUsuario);

    res.status(201).json({
        mensaje: "Usuario agregado correctamente",
        usuario: nuevoUsuario
    });
});

// Login con JWT
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            mensaje: "Debe proporcionar usuario y contraseña"
        });
    }

    const usuarioEncontrado = usuariosRegistrados.find(
        usuario =>
            usuario.username === username &&
            usuario.password === password
    );

    if (!usuarioEncontrado) {
        console.warn(
            `[ALERTA] Intento de inicio de sesion fallido para: ${username}`
        );

        return res.status(401).json({
            mensaje: "Credenciales incorrectas"
        });
    }

    const token = jwt.sign(
        {
            id: usuarioEncontrado.id,
            username: usuarioEncontrado.username,
            role: usuarioEncontrado.role
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    console.log(
        `[LOGIN CORRECTO] Usuario: ${usuarioEncontrado.username} | Rol: ${usuarioEncontrado.role}`
    );

    res.json({
        mensaje: "Autenticacion exitosa",
        token,
        usuario: {
            username: usuarioEncontrado.username,
            role: usuarioEncontrado.role
        }
    });
});

// Verificar token JWT
function verificarToken(req, res, next) {
    const authorizationHeader = req.headers.authorization;

    if (!authorizationHeader) {
        console.warn("[ACCESO DENEGADO] Solicitud sin token");

        return res.status(401).json({
            mensaje: "Acceso denegado. No se proporciono un token"
        });
    }

    const partes = authorizationHeader.split(" ");

    if (partes.length !== 2 || partes[0] !== "Bearer") {
        return res.status(401).json({
            mensaje: "Formato incorrecto. Debe usar: Bearer TOKEN"
        });
    }

    const token = partes[1];

    try {
        const tokenVerificado = jwt.verify(token, JWT_SECRET);

        req.user = tokenVerificado;
        next();
    } catch (error) {
        console.warn(`[TOKEN RECHAZADO] ${error.message}`);

        return res.status(403).json({
            mensaje: "Token invalido o expirado"
        });
    }
}

// Verificar rol
function verificarRol(rolPermitido) {
    return (req, res, next) => {
        if (req.user.role !== rolPermitido) {
            console.warn(
                `[ACCESO PROHIBIDO] Usuario: ${req.user.username} | Rol actual: ${req.user.role} | Rol requerido: ${rolPermitido}`
            );

            return res.status(403).json({
                mensaje: "No tiene permisos para acceder a esta ruta"
            });
        }

        next();
    };
}

// Ruta protegida
app.get("/secure-data", verificarToken, (req, res) => {
    res.json({
        mensaje: "Acceso permitido a la informacion protegida",
        usuario: req.user.username,
        role: req.user.role,
        informacion: "Estos datos solamente pueden verse con un token valido"
    });
});

// Ruta exclusiva para administrador
app.get(
    "/admin",
    verificarToken,
    verificarRol("admin"),
    (req, res) => {
        res.json({
            mensaje: "Bienvenido al panel administrativo",
            usuario: req.user.username,
            role: req.user.role
        });
    }
);

// Crear usuario como administrador
app.post(
    "/admin/users",
    verificarToken,
    verificarRol("admin"),
    (req, res) => {
        const { nombre, correo } = req.body;

        if (!nombre || !correo) {
            return res.status(400).json({
                mensaje: "El nombre y el correo son obligatorios"
            });
        }

        const nuevoUsuario = {
            id: users.length + 1,
            nombre,
            correo
        };

        users.push(nuevoUsuario);

        console.log(
            `[USUARIO CREADO] Administrador: ${req.user.username} | Nuevo usuario: ${nombre}`
        );

        res.status(201).json({
            mensaje: "Usuario creado por el administrador",
            usuario: nuevoUsuario
        });
    }
);

// Ruta inexistente
app.use((req, res) => {
    res.status(404).json({
        mensaje: "La ruta solicitada no existe"
    });
});

// Iniciar servidor
app.listen(PORT, "0.0.0.0", () => {
    console.log(`API segura funcionando en el puerto ${PORT}`);
});