import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { login, logout, register } from "./user.controller";


export async function userRoutes(app: FastifyInstance)
{
	app.get('/', (req: FastifyRequest, res: FastifyReply)=>{
		res.send({"message": "/ route"})
	})
	app.post('/register', {schema: userSchema}, register)
	app.post('/login', {schema: userSchema}, login)
	app.post('/logout', logout)
}