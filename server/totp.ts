import Fastify from 'fastify';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const fastify = Fastify();

interface SetupBody {
  userId: string;
}

interface VerifyBody {
  userId: string;
  token: string;
}

fastify.post<{ Body: SetupBody }>('/2fa/setup', async (request, reply) => {
  const { userId } = request.body;

  const secret = speakeasy.generateSecret({
    name: `YourAppName (${userId})`,
    length: 20,
  });

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

  return reply.send({
    secret: secret.base32,
    qrCodeDataUrl,
  });
});

fastify.post<{ Body: VerifyBody }>('/2fa/verify', async (request, reply) => {
  const { userId, token } = request.body;

  // Replace with actual secret from DB:
  const userSecret = 'USER_SAVED_BASE32_SECRET';

  const verified = speakeasy.totp.verify({
    secret: userSecret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (verified) {
    return reply.send({ success: true, message: '2FA token valid' });
  } else {
    return reply.status(400).send({ success: false, message: 'Invalid 2FA token' });
  }
});

fastify.listen({ port: 3000 }, err => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log('Server listening on http://localhost:3000');
});
