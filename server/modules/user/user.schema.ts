const userSchema = {
	body: {
	  type: "object",
	  required: ["name", "email", "password"],
	  properties: {
		name: {type: "string"},
		email: { type: "string", format: "email" },
		password: { type: "string", minLength: 8 }
	  }
	},
	response: {
	  200: {
		type: "object",
		properties: {
		  id: { type: "string" },
		  email: { type: "string" },
		  name: {type: "string"}
		}
	  }
	}
  };