import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { login, logout, register } from "./user_controller.js";
// import {userSchema} from "./user_schema.js"


export async function userRoutes(app: FastifyInstance)
{
	app.get('/', (req: FastifyRequest, res: FastifyReply)=>{
		res.send({"message": "/ route"})
	})
	app.post('/register', register)
	app.post('/login', login)
	app.post('/logout', logout)
}