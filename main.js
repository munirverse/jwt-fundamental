const express = require("express");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();

function AppError(
  { httpErrorStatusCode, errorMessage } = {
    httpErrorStatusCode: 500,
    errorMessage: "default error",
  }
) {
  Error.call(this);
  Error.captureStackTrace(this);
  this.httpErrorCodeStatus = httpErrorStatusCode;
  this.message = errorMessage;
}

AppError.prototype = Object.create(Error.prototype);
AppError.prototype.constructor = AppError;

const authMiddleware = (req, res, next) => {
  try {
    if (!req?.headers?.authorization)
      throw new AppError({
        httpErrorStatusCode: 400,
        errorMessage: "not found token authorization",
      });

    const [_, token] = req.headers.authorization.split(" ");
    if (!token)
      throw new AppError({
        httpErrorStatusCode: 400,
        errorMessage: "invalid format token authorization",
      });

    req.user = jwt.verify(
      token,
      Buffer.from(process.env.JWT_SECRET_KEY, "base64url")
    );

    next();
  } catch (error) {
    next(error);
  }
};

app.get("/profiles", authMiddleware, (req, res) => {
  return res
    .status(200)
    .json({ message: `success get profile ${req.user.name}`, data: req.user });
});

app.get("/profiles2", (req, res, next) => {
  try {
    const username = req.headers?.["x-jwt-username"];
    const sub = req.headers?.["x-jwt-sub"];
    const iat = req.headers?.["x-jwt-iat"];

    if (!username || !sub || !iat) {
      console.log(username, sub, iat);

      throw new AppError({
        httpErrorStatusCode: 500,
        errorMessage: "cannot read jwt payload",
      });
    }

    return res.status(200).json({
      message: `success get profile ${username}`,
      data: { username, sub, iat },
    });
  } catch (error) {
    next(error);
  }
});

app.use((err, _, res, next) => {
  console.error(err);

  const httpStatusCode = err?.httpErrorStatusCode || 500;
  const errorMessage = err?.message || "GLOBAL ERROR";

  return res.status(httpStatusCode).json({ message: errorMessage });
});

app.listen(process.env.NODE_PORT, () =>
  console.log(`server running on port ${process.env.NODE_PORT}`)
);
