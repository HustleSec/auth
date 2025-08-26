import jwt from 'jsonwebtoken';

const JWT_SECRET = 'secret-key';
const ACCESS_TOKEN_EXPIRES = '15m';
const REFRESH_TOKEN_EXPIRES = '7d';

interface userInfo
{
	username: string;
	id: number
	email: string
}

export function createAccessToken(user: userInfo) {
  return jwt.sign({ UserInfo: { username: user.username, email: user.email, id : user.id} }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });
}

export function createRefreshToken(user: userInfo) {
  return jwt.sign({ UserInfo: { username: user.username, email: user.email, id : user.id} }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES });
}