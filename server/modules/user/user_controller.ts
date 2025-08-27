import fastify, { FastifyReply, FastifyRequest } from "fastify";
import bcrypt from "bcrypt"
import { init } from "../../db/db.js";
import {createAccessToken, createRefreshToken} from "../../token/generateToken.js"
import jwt from "jsonwebtoken"
import cookie from "@fastify/cookie";


const JWT_SECRET = 'secret-key';


interface loginBody
{
	name: string;
	email: string;
	password: string;
}


export async function register(req: FastifyRequest<{Body: loginBody}>, res: FastifyReply)
{
	const db = await init()
	const {password, name, email} = req.body
	if (!password || !name || !email)
		res.status(400).send("password email name are all required")
	const hashPassword = await bcrypt.hash(password, 10)
	
	try{
		var user = await db.get('SELECT * FROM users WHERE email = ?', email);
		if (user)
				return res.code(400).send({ error: 'user already exists' });
			await db.run(
				'INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
				[name,
					email,
					hashPassword]
				);
		user = await db.get('SELECT * FROM users WHERE email = ?', email);
		const accessToken = createAccessToken(user);
		const refreshToken = createRefreshToken(user);
	    return res
		.setCookie("accessToken", accessToken, {
			httpOnly: true,
			path: "/",
			sameSite: "lax"
		  })
		.setCookie("refreshToken", refreshToken, {
			httpOnly: true,
			path: "/",
			sameSite: "lax"
		  })
		.send({ message: 'register successful' });
	} catch(err: any){
		if (err.code === 'SQLITE_CONSTRAINT') {
			return res.code(400).send({ error: 'user already exists' });
		  }
		  return res.code(500).send({ error: 'Internal server error', err });
	}

}

export async function login(req: FastifyRequest<{Body: loginBody}>, res: FastifyReply)
{
	const db = await init()
	const {password, name, email} = req.body
	console.log(req.body)
	if (!password || !name || !email)
		res.status(400).send("password email name are all required")
	const user = await db.get('SELECT * FROM users WHERE email = ?', email);
	if (!user)
		res.status(400).send("invalid credentials")
	const valid = await bcrypt.compare(password, user.password);
	if (!valid)
		res.status(400).send("invalid credentials")


	const accessToken = createAccessToken(user);
 	const refreshToken = createRefreshToken(user);

	res
	.setCookie("accessToken", accessToken, {httpOnly: true, path: "/", sameSite: "lax"})
	.setCookie("refreshToken", refreshToken, {httpOnly: true, path: "/", sameSite: "lax"})
	.send({ message: 'Login successful' });
}

export async function logout(req: FastifyRequest, res: FastifyReply)
{
	res
	.clearCookie("accessToken", { httpOnly: true, path: "/", sameSite: "lax" })
	.clearCookie("refreshToken", { httpOnly: true, path: "/", sameSite: "lax" })
	.code(200)
	.send({ message: 'Logged out successfully' });
}

async function verifyJWT(req: FastifyRequest, reply: FastifyReply) 
{
	const token = req.cookies.accessToken;
	if (!token) return reply.code(401).send({ error: 'Unauthorized' });
  
	try {
	  const payload = jwt.verify(token, JWT_SECRET);
	  return payload;
	} catch {
	  return reply.code(401).send({ error: 'Invalid token' });
	}
}

export async function refreshToken(req: FastifyRequest, reply: FastifyReply)
{
	const token:any = req.cookies.refreshToken
	if (!token)
		reply.status(400).send({error: "no refresh token"})
	try {
		const payload = jwt.verify(token, JWT_SECRET)
		
		const newAccessToken  = createAccessToken(payload)
		const newRefreshToken = createRefreshToken(payload)
		reply
		.clearCookie("accessToken", { httpOnly: true, path: "/", sameSite: "lax" })
		.clearCookie("refreshToken", { httpOnly: true, path: "/", sameSite: "lax" })
		.setCookie("accessToken", newAccessToken, {httpOnly: true, path: "/", sameSite: "lax"})
		.setCookie("refreshToken", newRefreshToken, {httpOnly: true, path: "/", sameSite: "lax"})
		.send({ message: 'Token refreshed' });
	} catch (error:any) {
		return reply.status(400).send({"invalid token : ": error.message})
	}
}

export async function authMiddleware(req: FastifyRequest, reply: FastifyReply) {
	const token = req.cookies.accessToken
	if (!token) {
	  return reply.code(401).send({ error: "Unauthorized" });
	}

	try {
	  const payload = jwt.verify(token, JWT_SECRET);
	  (req as any).user = payload;
	} catch {
	  return reply.code(401).send({ error: "Invalid token" });
	}
}