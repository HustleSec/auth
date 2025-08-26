import fastify from "fastify";
import { userRoutes } from "./modules/user/user.route";
import cookie from "fastify-cookie";

const app = fastify({ logger: true })

app.register(userRoutes, {prefix: 'api/user'})
app.register(cookie);
app.addSchema(userSchema)

async function main() {
	await app.listen({
		port: 8000
	})
}
main()