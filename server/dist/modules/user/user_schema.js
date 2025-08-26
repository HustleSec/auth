export const userBodySchema = {
    $id: 'user-body-schema',
    type: "object",
    required: ["name", "email", "password"],
    properties: {
        name: { type: "string" },
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 }
    }
};
export const userResponseSchema = {
    $id: 'user-response-schema',
    type: "object",
    properties: {
        id: { type: "string" },
        email: { type: "string" },
        name: { type: "string" }
    }
};
