import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// CONFIGURAR
const secretKey = '5d809532790664aaf999c5799e1ac53dc131a61db576a20c095673c9dcbbae0b';

// EXPRESS
const app = express();

// ANALISIS SOLICITUDES
app.use(express.json());

// SE PUEDE ALMACENAR EN MONGO
const users = [
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
app.post('/api/register', (req: Request, res: Response) => {
  const { username, password } = req.body;

  // SI YA EXISTE
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: 'El nombre de usuario ya esta registrado.' });
  }

  // ID UNICO
  const id = users.length + 1;

  // ENCRIPTAR CONTRASEÑA
  const hashedPassword = bcrypt.hashSync(password, 10);

  // CREAR EL USUARIO
  const newUser = {
    id,
    username,
    password: hashedPassword,
  };

  // AGREGAR A LA LISTA
  users.push(newUser);

  return res.json({ userCreated: newUser });
});

// INICIO DE SESION
app.post('/api/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  // BUSQUEDA DEL USUARIO
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Nombre de usuario o contraseña incorrectos.' });
  }

  // VALIDAR CONTRASEÑA
  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ message: 'Nombre de usuario o contraseña incorrectos.' });
  }

  // AUTENTICACION
  const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });

  return res.json({ user, token });
});

// BUSQUEDA DE USUARIOS PROTEGIDA
app.get('/api/users', authenticateToken, (req: Request, res: Response) => {
  // AQUI CONSULTA LA BASE DE DATOS
  const usersWithoutPasswords = users.map((user) => {
    const { id, username } = user;
    return { id, username };
  });

  return res.json(usersWithoutPasswords);
});

// AUTENTICACION DEL TOKEN
function authenticateToken(req: Request, res: Response, next: any) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No autorizado.' });
  }

  jwt.verify(token, secretKey, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: 'No autorizado.' });
    }
    req.user = user;
    next();
  });
}

// INICIAR
app.listen(3000, () => {
  console.log('Servidor en funcionamiento en el puerto 3000.');
});
