import nodemailer from "nodemailer";
import crypto from "crypto";
import { FastifyReply, FastifyRequest } from "fastify";
import { init } from "../db/db.js";
import {createAccessToken, createRefreshToken} from "../token/generateToken.js"

interface login
{
	email: string;
	name: string;
	password: string;
}

interface two_factor
{
	email: string;
	code: string;
}

const transporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
	  user: "domainnetworkus@gmail.com",
	  pass: "krrv avqr rkgc waju",
	},
  });

export async function send2fcode(req: FastifyRequest<{Body: login}>,  reply: FastifyReply)
{
	const { email } = req.body

	const code = crypto.randomInt(100000, 999999).toString()
	const db = await init()
	await db.run(
		"UPDATE users SET 2fa_code=?, 2fa_expiry=? WHERE email=?",
		[code, Date.now() + 5 * 60 * 1000, email]
	);

	await transporter.sendMail({
		from: '"Transcendence" <no-reply@myapp.com>',
		to: email,
		subject: "Your login code",
		text: `Your 2FA code is: ${code}`,
	  });
	
	return reply.send({ message: "2FA code sent to email" });
}

export async function verify2fa(req: FastifyRequest<{Body: two_factor}>, res: FastifyReply)
{
	const {email, code} = req.body
	const db = await init()
	const user = await db.get("SELECT * from users WHERE email=?", [email])
	if (!user || !user["2fa_code"])
		return res.status(400).send({ error: "No 2FA request found" })
	if (Date.now() > user["2fa_expiry"])
		return res.status(400).send({ error: "Code expired" })
	if (code != user["2fa_code"])
		return res.status(400).send({ error: "invalid code" })
	db.run("UPDATE users SET 2fa_code=NULL, 2fa_expiry=NULL WHERE email=?", [email])
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
}