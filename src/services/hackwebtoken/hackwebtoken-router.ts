import { Request, Response, Router } from 'express';
import crypto from 'crypto';
import { StatusCode } from 'status-code-enum';
import cors from 'cors';

const encodingRouter = Router();
encodingRouter.use(cors());
const SECRET_KEY = crypto.randomBytes(32).toString('base64');


const base64UrlEncode = (input: Buffer) => {
    return input.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};


const base64UrlDecode = (input: string) => {
    input = input
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const pad = input.length % 4;
    if (pad) {
        input += '='.repeat(4 - pad);
    }
    return Buffer.from(input, 'base64');
};


const createSignature = (header: string, payload: string, secret: string) => {
    const data = `${header}.${payload}`;
    return base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest());
};

encodingRouter.post('/encode/', async (req: Request, res: Response) => {
    console.log('Encoding request received');
    const { user, data, context } = req.body;
    console.log(user);

    if (!user || !data) {
        return res.status(500).json({ error: 'Missing user or data' });
        // return res.status(StatusCode.ClientErrorBadRequest).json({ error: 'Missing user or data' });
    }

    try {
        const header = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
        const payload = JSON.stringify({ user, data });
        const encodedHeader = base64UrlEncode(Buffer.from(header));
        const encodedPayload = base64UrlEncode(Buffer.from(payload));
        const signature = createSignature(encodedHeader, encodedPayload, SECRET_KEY);

        const token = `${encodedHeader}.${encodedPayload}.${signature}`;
        return res.status(StatusCode.SuccessOK).send({ token, context: context || {} });    // 
    } catch (err) {
        // return next(err);
        return res.status(500);
    }
});

encodingRouter.post('/decode/', async (req: Request, res: Response) => {
    console.log('Decoding request received');
    const { token } = req.body;
    console.log(token);

    if (!token) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: 'Missing token' });
    }

    try {
        const [encodedHeader, encodedPayload, receivedSignature] = token.split('.');
        const expectedSignature = createSignature(encodedHeader, encodedPayload, SECRET_KEY);

        if (receivedSignature !== expectedSignature) {
            return res.status(StatusCode.ClientErrorUnauthorized).json({ error: 'Invalid token' });
        }

        const payload = JSON.parse(base64UrlDecode(encodedPayload).toString());
        return res.status(StatusCode.SuccessOK).send({ user: payload.user, data: payload.data });
    } catch (err) {
        return res.status(StatusCode.ClientErrorUnauthorized).json({ error: 'Invalid token' });
    }
});

export default encodingRouter;