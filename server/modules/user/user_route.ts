import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { login, logout, register, refreshToken, authMiddleware } from "./user_controller.js";
// import {userSchema} from "./user_schema.js"


export async function userRoutes(app: FastifyInstance)
{
	app.get('/', (req: FastifyRequest, res: FastifyReply)=>{
		res.send({"test": req})
	})
	app.get("/profile", { preHandler: authMiddleware }, async (req, reply) => {
		return { message: "This is your profile!", user: (req as any).user };
	});
	app.post('/register', register)
	app.post('/login', login)
	app.post('/logout', logout)
	app.post('/auth/refresh', refreshToken)
}