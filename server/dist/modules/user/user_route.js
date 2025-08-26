import { login, logout, register } from "./user_controller.js";
// import {userSchema} from "./user_schema.js"
export async function userRoutes(app) {
    app.get('/', (req, res) => {
        res.send({ "message": "/ route" });
    });
    app.post('/register', register);
    app.post('/login', login);
    app.post('/logout', logout);
}
