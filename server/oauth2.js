// app.js
const fastify = require('fastify')({ logger: true });
const fastifySession = require('@fastify/session');
const fastifyCookie = require('@fastify/cookie');
const fastifyPassport = require('@fastify/passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;


const users = new Map();

async function build() {
  await fastify.register(fastifyCookie);
  
  await fastify.register(fastifySession, {
    secret: 'abcdefghijklmnopqrstuvwxyz123456', // 32+ chars
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' }
  });

  await fastify.register(fastifyPassport.initialize());
  await fastify.register(fastifyPassport.secureSession());


  fastifyPassport.use('google', new GoogleStrategy({
    clientID: 'client id',
    clientSecret: 'client secret',
    callbackURL: 'http://localhost:3000/auth/google/callback',
    passReqToCallback: true
  }, (req, accessToken, refreshToken, profile, done) => {
    console.log('Google Profile:', profile);
    
    let user = users.get(profile.id);
    if (!user) {
      user = { 
        id: profile.id, 
        name: profile.displayName, 
        email: profile.emails && profile.emails[0] ? profile.emails[0].value : 'No email'
      };
      users.set(profile.id, user);
      console.log('Created new user:', user);
    }
    done(null, user);
  }));

  fastifyPassport.registerUserSerializer(async (user, request) => {
    console.log('Serializing user:', user.id);
    return user.id;
  });
  
  fastifyPassport.registerUserDeserializer(async (id, request) => {
    console.log('Deserializing user ID:', id);
    const user = users.get(id);
    console.log('Found user:', user);
    return user;
  });


  fastify.get('/auth/google', {
    preValidation: fastifyPassport.authenticate('google', { 
      scope: ['email', 'profile'] 
    })
  }, async (req, reply) => {
    reply.send('Redirecting...');
  });

  // 2. OAuth callback
  fastify.get('/auth/google/callback', {
    preValidation: fastifyPassport.authenticate('google', {
      successRedirect: '/dashboard',
      failureRedirect: '/login?error=auth_failed'
    })
  }, async (req, reply) => {
    reply.send('Processing...');
  });

  fastify.get('/dashboard', async (req, reply) => {
    console.log('Dashboard - req.user:', req.user);
    if (!req.user) {
      return reply.redirect('/login');
    }
    reply.send({ 
      message: 'Welcome to your dashboard!', 
      user: req.user 
    });
  });

  fastify.get('/login', async (req, reply) => {
    const error = req.query.error;
    reply.send({ 
      message: 'Please log in with Google', 
      error,
      loginUrl: '/auth/google'
    });
  });

  fastify.get('/logout', async (req, reply) => {
    req.logout();
    reply.redirect('/');
  });

  fastify.get('/', async (req, reply) => {
    reply.send(`
      <h1>Google OAuth Demo</h1>
      <p>User: ${req.user ? req.user.name : 'Not logged in'}</p>
      ${req.user 
        ? '<a href="/dashboard">Dashboard</a> | <a href="/logout">Logout</a>' 
        : '<a href="/auth/google">Login with Google</a>'
      }
    `);
  });

  return fastify;
}

async function start() {
  try {
    const app = await build();
    await app.listen({ port: 3000 });
  } catch (err) {
    process.exit(1);
  }
}

start();