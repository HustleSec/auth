import bcrypt from "bcrypt";
import { init } from "../../db/db.js";
import { createAccessToken, createRefreshToken } from "../../token/generateToken.js";
import jwt from "jsonwebtoken";
const JWT_SECRET = 'secret-key';
export async function register(req, res) {
    const db = await init();
    const { password, name, email } = req.body;
    if (!password || !name || !email)
        res.status(400).send("password email name are all required");
    const hashPassword = bcrypt.hash(password, 10);
    try {
        const result = await db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', name, email, hashPassword);
        const user = await db.get('SELECT * FROM users WHERE email = ?', email);
        const accessToken = createAccessToken(user);
        const refreshToken = createRefreshToken(user);
        return res
            .setCookie('accessToken', accessToken, { httpOnly: true })
            .setCookie('refreshToken', refreshToken, { httpOnly: true })
            .send({ message: 'register successful' });
    }
    catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
            return res.code(400).send({ error: 'user already exists' });
        }
        return res.code(500).send({ error: 'Internal server error' });
    }
}
export async function login(req, res) {
    const db = await init();
    const { password, name, email } = req.body;
    if (!password || !name || !email)
        res.status(400).send("password email name are all required");
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (!user)
        res.status(400).send("invalid credentials");
    const valid = bcrypt.compare(password, user.password);
    if (!valid)
        res.status(400).send("invalid credentials");
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);
    res
        .setCookie('accessToken', accessToken, { httpOnly: true })
        .setCookie('refreshToken', refreshToken, { httpOnly: true })
        .send({ message: 'Login successful' });
}
export async function logout(req, res) {
    res
        .clearCookie('accessToken', { path: '/' })
        .clearCookie('refreshToken', { path: '/' })
        .code(200)
        .send({ message: 'Logged out successfully' });
}
async function verifyJWT(req, reply) {
    const token = req.cookies.accessToken;
    if (!token)
        return reply.code(401).send({ error: 'Unauthorized' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        return payload;
    }
    catch {
        return reply.code(401).send({ error: 'Invalid token' });
    }
}
