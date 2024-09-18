import { Request, Response, Router } from "express";
import crypto from "crypto";
import { StatusCode } from "status-code-enum";
import cors from "cors";
import { NextFunction } from "express-serve-static-core";

// TODO: fix apidocs warnings -- not sure how to fix that?????
// TODO: test suite
// TODO: if time permits -- better the encoding

const encodingRouter = Router();
encodingRouter.use(cors());
// to avoid magic numbers
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
 * @api {post} /hackwebtoken/encode/ Encode JWT Token
 * @apiName EncodeJWT
 * @apiGroup HackWebToken
 * @apiDescription Encode user data into a JWT token.
 *
 * @apiHeader {String} Content-Type application/json
 * @apiParam {String} user The username of the user.
 * @apiParam {Object} data The data to be encoded in the token.
 * @apiParam (data) {String} role The role of the user.
 * @apiParam (data) {Number} access_level The access level of the user.
 *
 * @apiSuccess {String} token The generated JWT token.
 * @apiSuccess {String} context Some extra data.
 *
 * @apiError (400) BadRequest Missing user or data.
 * @apiError (500) InternalServerError Server error.
 */
encodingRouter.post("/encode/", async (req: Request, res: Response, next: NextFunction) => {
    console.log("Encoding request received");
    const { user, data } = req.body;

    if (!user || !data) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Missing user or data" });
    }

    try {
        const uniqueId = crypto.randomBytes(16).toString("hex");
        const timestamp = new Date().toISOString();

        const header = JSON.stringify({ alg: "HS256", typ: "JWT" });
        const payload = JSON.stringify({ user, data, uniqueId, timestamp });
        const encodedHeader = base64UrlEncode(Buffer.from(header));
        const encodedPayload = base64UrlEncode(Buffer.from(payload));
        const signature = createSignature(encodedHeader, encodedPayload, SECRET_KEY);

        const token = `${encodedHeader}.${encodedPayload}.${signature}`;
        const context = "some extra data"; // doc said this
        return res.status(StatusCode.SuccessOK).send({ token, context: context || {} });
    } catch (err) {
        return next(err);
    }
});

/**
 * @api {post} /hackwebtoken/decode/ Decode JWT Token
 * @apiName DecodeJWT
 * @apiGroup HackWebToken
 * @apiDescription Decode a JWT token and retrieve the encoded user data.
 *
 * @apiHeader {String} Content-Type application/json
 * @apiParam {String} token The JWT token to decode.
 *
 * @apiSuccess {String} user The username of the user.
 * @apiSuccess {Object} data The decoded data from the token.
 * @apiSuccess (data) {String} role The role of the user.
 * @apiSuccess (data) {Number} access_level The access level of the user.
 *
 * @apiError (400) BadRequest Missing token.
 * @apiError (401) Unauthorized Invalid token.
 * @apiError (500) InternalServerError Server error.
 */
encodingRouter.post("/decode/", async (req: Request, res: Response) => {
    console.log("Decoding request received");
    const { token } = req.body;

    if (!token) {
        return res.status(StatusCode.ClientErrorBadRequest).json({ error: "Missing token" });
    }

    try {
        const [encodedHeader, encodedPayload, receivedSignature] = token.split(".");
        const expectedSignature = createSignature(encodedHeader, encodedPayload, SECRET_KEY);

        if (receivedSignature !== expectedSignature) {
            return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Invalid token" });
        }

        const payload = JSON.parse(base64UrlDecode(encodedPayload).toString());
        return res.status(StatusCode.SuccessOK).send({ user: payload.user, data: payload.data });
    } catch (err) {
        return res.status(StatusCode.ClientErrorUnauthorized).json({ error: "Invalid token" });
    }
});

export default encodingRouter;
