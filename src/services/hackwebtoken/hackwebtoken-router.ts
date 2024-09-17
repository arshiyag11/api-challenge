import { Request, Response, Router } from "express";
import crypto from "crypto";
import { StatusCode } from "status-code-enum";
import cors from "cors";
import { NextFunction } from "express-serve-static-core";

const encodingRouter = Router();
encodingRouter.use(cors());
const SECRET_KEY_LENGTH = 32;
const BASE64_PADDING_DIVISOR = 4;
const SECRET_KEY = crypto.randomBytes(SECRET_KEY_LENGTH).toString("base64");

const base64UrlEncode = (input: Buffer): string =>
    input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const base64UrlDecode = (input: string): Buffer => {
    input = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = input.length % BASE64_PADDING_DIVISOR;
    if (pad) {
        input += "=".repeat(BASE64_PADDING_DIVISOR - pad);
    }
    return Buffer.from(input, "base64");
};

const createSignature = (header: string, payload: string, secret: string): string => {
    const data = `${header}.${payload}`;
    return base64UrlEncode(crypto.createHmac("sha256", secret).update(data).digest());
};

/**
 * @api {post} /hackwebtoken/encode/ POST /hackwebtoken/encode/
 * @apiGroup HackWebToken
 * @apiDescription Implement a JWT Token: encoding
 *
 * @apiHeader {String} Content-Type: application/json
 *
 * @apiBody {String} user, data
 *
 * @apiSuccessExample Example Success Response:
 * HTTP/1.1 200 OK
 * {token: encoded token, context: "some extra data"}
 */
encodingRouter.post("/encode/", async (req: Request, res: Response, next: NextFunction) => {
    console.log("Encoding request received");
    const { user, data } = req.body;

    if (!user || !data) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Missing user or data" });
    }

    try {
        const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
        const payload = JSON.stringify({ user, data });
        const encodedHeader = base64UrlEncode(Buffer.from(header));
        const encodedPayload = base64UrlEncode(Buffer.from(payload));
        const signature = createSignature(encodedHeader as string, encodedPayload as string, SECRET_KEY as string);

        const token = `${encodedHeader as string}.${encodedPayload as string}.${signature as string}`;
        const context = "some extra data";
        return res.status(StatusCode.SuccessOK).send({ token, context: context || {} });
    } catch (err) {
        return next(err);
    }
});

/**
 * @api {post} /hackwebtoken/decode/ POST /hackwebtoken/decode/
 * @apiGroup HackWebToken
 * @apiDescription Implement a JWT Token: decoding
 *
 * @apiHeader {String} Content-Type: application/json
 *
 * @apiBody {String} token, context
 *
 * @apiSuccessExample Example Success Response:
 * HTTP/1.1 200 OK
 * {user: decoded user, data: {role: role, access_level: number}}
 */

encodingRouter.post("/decode/", async (req: Request, res: Response) => {
    console.log("Decoding request received");
    const { token } = req.body;

    if (!token) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Missing token" });
    }

    try {
        const [encodedHeader, encodedPayload, receivedSignature] = token.split(".");
        const expectedSignature = createSignature(encodedHeader as string, encodedPayload as string, SECRET_KEY as string);

        if (receivedSignature !== expectedSignature) {
            return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Invalid token" });
        }

        const payload = JSON.parse(base64UrlDecode(encodedPayload as string).toString());
        return res.status(StatusCode.SuccessOK).send({ user: payload.user, data: payload.data });
    } catch (err) {
        return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Invalid token" });
    }
});

export default encodingRouter;
