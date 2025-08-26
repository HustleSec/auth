import fastify from "fastify";
import { userRoutes } from "./modules/user/user_route.js";
import cookie from "@fastify/cookie";
import {userResponseSchema, userBodySchema} from "./modules/user/user_schema.js"

const app = fastify({ logger: true })

app.register(userRoutes, {prefix: 'api/user'})
app.register(cookie);
// app.addSchema(userResponseSchema)
// app.addSchema(userBodySchema)

async function main() {
	await app.listen({
		port: 8000
	})
}
main()