const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const path = require('path');
const cookieParser = require('cookie-parser');
const app = express();
const PORT = 3000;
const secretKey = 'yourSecretKey';

const publicDirName = 'client'

app.use(cookieParser());
app.use(express.json());

const userDb = new Map()

// Функция для генерации JWT токена
const generateToken = ({ username }) => {
    return jwt.sign({ username }, secretKey, { expiresIn: '1h' });
}

// Returns user by token if user exists
const getUserByDecodedToken = (decoded) => {
    const userName = decoded?.username || ''
    const currentUser = userDb.get(userName)

    return currentUser
}

// Checks authorization request on express validation errors
const checkAuthRequestBody = (req, res, next) => {
    const errors = validationResult(req);
    const requestBodyHasError = !errors.isEmpty()

    if (requestBodyHasError) return res.status(422).json({ errors: errors.array() });

    next()
}

// Промежуточное ПО для проверки JWT токена
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        const user = getUserByDecodedToken(decoded)

        if (err || !user) {
            return res.status(403).json({ message: 'Invalid token' });
        }

        next();
    });
}

// If token doesn't exist in browser cookie, will not allow access on pages which require authentication
const allowPageByToken = (req, res, next) => {
    const token = req.cookies.token

    if (!token) return res.redirect('/login');

    jwt.verify(token, secretKey, (err, decoded) => {
        const user = getUserByDecodedToken(decoded)

        if (err || !user) return res.redirect('/login');

        next();
    });
}

app.post('/registration',
    body('username').notEmpty(),
    body('password').notEmpty(),
    checkAuthRequestBody,
    (req, res) => {
        try {
            const errors = validationResult(req);
            const requestBodyHasError = !errors.isEmpty()

            if (requestBodyHasError) return res.status(422).json({ errors: errors.array() });

            const { username, password } = req.body;
            const user = { username, password };

            if (userDb.get(username)) throw new Error('This user is already exist!')

            userDb.set(username, user)

            return res.status(200).send({
                message: 'User has successfully added!',
                data: user
            })
        } catch (error) {
            return res.status(500).send(error.message)
        }
    })

// Пример простой аутентификации (здесь без проверки пароля)
app.post('/login',
    body('username').notEmpty(),
    body('password').notEmpty(),
    checkAuthRequestBody,
    (req, res) => {
        try {

            const { username, password } = req.body;
            // Проверка пользователя (например, из базы данных)
            const expectedUser = userDb.get(username)
            const userIsNotExist = !expectedUser

            if (userIsNotExist) throw new Error('User is not exist!')

            const userPassIsNotValid = expectedUser.password !== password

            if (userPassIsNotValid) throw new Error('Login error: User password is not valid!')
            // Пользователь успешно аутентифицирован
            const user = { username, password };

            // Генерация JWT токена
            const token = generateToken(user);

            return res.json({ token });
        } catch (error) {
            return res.status(500).send(error.message)
        }
    });

// Пример защищенного маршрута, требующего аутентификации
app.get('/protected', verifyToken, (req, res) => {
    // Если токен верифицирован, отправляем защищенные данные
    res.json({ message: 'This is a protected route!' });
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, publicDirName, 'router', 'login.html'));
});

app.get('/registration', (req, res) => {
    res.sendFile(path.join(__dirname, publicDirName, 'router', 'registration.html'));
});

app.get('/', allowPageByToken, (req, res) => {
    res.sendFile(path.join(__dirname, publicDirName, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
