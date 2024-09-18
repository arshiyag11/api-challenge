import request from "supertest";
import express from "express";
import encodingRouter from "./hackwebtoken-router";
import { describe, expect, it } from "@jest/globals";

const app = express();
app.use(express.json());
app.use("/hackwebtoken/", encodingRouter);

describe("JWT Encoding and Decoding", () => {
    let validToken: string;

    it("TEST1: should encode data and return a token", async () => {
        const response = await request(app)
            .post("/hackwebtoken/encode/")
            .send({ user: "John_Doe", data: { role: "admin", access_level: 5 } })
            .expect(200);

        expect(response.body).toHaveProperty("token");
        expect(response.body).toHaveProperty("context");
        validToken = response.body.token;
    });

    it("TEST2: should decode a valid token and return the original data", async () => {
        expect(validToken).toBeDefined();

        const response = await request(app).post("/hackwebtoken/decode/").send({ token: validToken }).expect(200);

        expect(response.body).toHaveProperty("user", "John_Doe");
        expect(response.body).toHaveProperty("data");
        expect(response.body.data).toEqual({ role: "admin", access_level: 5 });
    });

    it("TEST3: should return an error for an invalid token", async () => {
        const invalidToken = `${"a".repeat(43)}.${"b".repeat(43)}.${"c".repeat(43)}`;

        const response = await request(app).post("/hackwebtoken/decode/").send({ token: invalidToken }).expect(401);

        expect(response.body).toHaveProperty("error", "Invalid token"); // works
    });

    it("TEST4: should return an error if no token is provided for decoding", async () => {
        const response = await request(app).post("/hackwebtoken/decode/").send({}).expect(400);

        expect(response.body).toHaveProperty("error", "Missing token"); // works
    });

    it("TEST5: should return an error if user or data is missing for encoding", async () => {
        const response = await request(app)
            .post("/hackwebtoken/encode/")
            .send({ data: { role: "admin", access_level: 5 } })
            .expect(400);
        expect(response.body).toHaveProperty("error", "Missing user or data"); // works
    });
});
