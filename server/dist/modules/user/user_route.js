import { login, logout, register, refreshToken, authMiddleware } from "./user_controller.js";
// import {userSchema} from "./user_schema.js"
export async function userRoutes(app) {
    app.get('/', (req, res) => {
        res.send({ "test": req });
    });
    app.get("/profile", { preHandler: authMiddleware }, async (req, reply) => {
        return { message: "This is your profile!", user: req.user };
    });
    app.post('/register', register);
    app.post('/login', login);
    app.post('/logout', logout);
    app.post('/auth/refresh', refreshToken);
}
