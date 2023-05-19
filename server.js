"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = require("express");
var bcrypt_1 = require("bcrypt");
var jsonwebtoken_1 = require("jsonwebtoken");
// CONFIGURAR
var secretKey = '5d809532790664aaf999c5799e1ac53dc131a61db576a20c095673c9dcbbae0b';
// EXPRESS
var app = express();
// ANALISIS SOLICITUDES
app.use(express_1.default.json());
// SE PUEDE ALMACENAR EN MONGO
var users = [
    {
        id: 1,
        username: 'user1',
        password: '$2b$10$GRv3lO05cNlkwQb6xCeTjeL9rI1u/cFadwf6/qFQDpBrH35/ApArO', // : password1
    },
    {
        id: 2,
        username: 'user2',
        password: '$2b$10$ZpItDnI/gGL3u0tWYsKrWuShrS65CNpMye46NNzUdd/7uoExFXQ4K', // : password2
    },
];
// REGISTRO USUARIOS
app.post('/api/register', function (req, res) {
    var _a = req.body, username = _a.username, password = _a.password;
    // SI YA EXISTE
    var existingUser = users.find(function (user) { return user.username === username; });
    if (existingUser) {
        return res.status(400).json({ message: 'El nombre de usuario ya esta registrado.' });
    }
    // ID UNICO
    var id = users.length + 1;
    // ENCRIPTAR CONTRASEÑA
    var hashedPassword = bcrypt_1.default.hashSync(password, 10);
    // CREAR EL USUARIO
    var newUser = {
        id: id,
        username: username,
        password: hashedPassword,
    };
    // AGREGAR A LA LISTA
    users.push(newUser);
    return res.json({ userCreated: newUser });
});
// INICIO DE SESION
app.post('/api/login', function (req, res) {
    var _a = req.body, username = _a.username, password = _a.password;
    // BUSQUEDA DEL USUARIO
    var user = users.find(function (u) { return u.username === username; });
    if (!user) {
        return res.status(401).json({ message: 'Nombre de usuario o contraseña incorrectos.' });
    }
    // VALIDAR CONTRASEÑA
    var passwordMatch = bcrypt_1.default.compareSync(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ message: 'Nombre de usuario o contraseña incorrectos.' });
    }
    // AUTENTICACION
    var token = jsonwebtoken_1.default.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
    return res.json({ user: user, token: token });
});
// BUSQUEDA DE USUARIOS PROTEGIDA
app.get('/api/users', authenticateToken, function (req, res) {
    // AQUI CONSULTA LA BASE DE DATOS
    var usersWithoutPasswords = users.map(function (user) {
        var id = user.id, username = user.username;
        return { id: id, username: username };
    });
    return res.json(usersWithoutPasswords);
});
// AUTENTICACION DEL TOKEN
function authenticateToken(req, res, next) {
    var authHeader = req.headers['authorization'];
    var token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'No autorizado.' });
    }
    jsonwebtoken_1.default.verify(token, secretKey, function (err, user) {
        if (err) {
            return res.status(403).json({ message: 'No autorizado.' });
        }
        req.user = user;
        next();
    });
}
// INICIAR
app.listen(3000, function () {
    console.log('Servidor en funcionamiento en el puerto 3000.');
});
