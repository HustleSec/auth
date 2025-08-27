import jwt from "jsonwebtoken"

const JWT_SECRET = 'secret-key';
const ACCESS_TOKEN_EXPIRES = '1m';
const REFRESH_TOKEN_EXPIRES = '7d';

export function createAccessToken(user:any) {
  return jwt.sign({ UserInfo: { username: user.username, email: user.email, id : user.id} }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });
}

export function createRefreshToken(user: any) {
  return jwt.sign({ UserInfo: { username: user.username, email: user.email, id : user.id} }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES });
}