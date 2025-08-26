import { login, logout, register } from "./user_controller";
import { userSchema } from "./user_schema";
export async function userRoutes(app) {
    app.get('/', (req, res) => {
        res.send({ "message": "/ route" });
    });
    app.post('/register', { schema: userSchema }, register);
    app.post('/login', { schema: userSchema }, login);
    app.post('/logout', logout);
}
