const { v4: uuidv4 } = require("uuid");
const {
  reqBody,
  multiUserMode,
  verifyJWT,
  createJWT,
} = require("../../utils/http");
const { Telemetry } = require("../../models/telemetry");
const { streamChatWithForEmbed } = require("../../utils/chats/embed");
const { EmbedChats } = require("../../models/embedChats");
const {
  validEmbedConfig,
  canRespond,
  setConnectionMeta,
} = require("../../utils/middleware/embedMiddleware");
const {
  promptUserForEmail,
  informInvalidEmail,
  promptUserForOTP,
  informOTPMismatch,
  verifiedOTP,
  invalidEmailExist,
  otpExpired,
  invalidOTP,
} = require("../../jobs/helpers/index");
const { User } = require("../../models/user");
const prisma = require("../../utils/prisma");
const {
  writeResponseChunk,
  convertToChatHistory,
} = require("../../utils/helpers/chat/responses");

let finalToken = "";
let finalSecret = "";
let emailValidated = false;

function embeddedEndpoints(app) {
  if (!app) return;

  let enterEmail = false;
  let sendOtp = false;
  let otpMatched = false;

  const sessionStore = {};

  function storeSessionData(ip, data) {
    sessionStore[ip] = data;
  }

  function getSessionData(ip) {
    return sessionStore[ip];
  }

  app.post(
    "/embed/:embedId/stream-chat",
    [validEmbedConfig, setConnectionMeta, canRespond],
    async (request, response) => {
      try {
        const clientIp =
          request.ip ||
          request.headers["x-forwarded-for"] ||
          request.connection.remoteAddress;
        let sessionData = getSessionData(clientIp) || {
          enterEmail: false,
          emailValidated: false,
          sendOtp: false,
          otpMatched: false,
        };
        const token = request.headers.authorization?.split(" ")[1];
        const verify = verifyJWT(token, request);

        if (token && verify) {
          const embed = response.locals.embedConfig;
          const {
            sessionId,
            message,
            prompt = null,
            model = null,
            temperature = null,
          } = reqBody(request);

          response.setHeader("Cache-Control", "no-cache");
          response.setHeader("Content-Type", "text/event-stream");
          response.setHeader("Access-Control-Allow-Origin", "*");
          response.setHeader("Connection", "keep-alive");
          response.flushHeaders();

          await streamChatWithForEmbed(response, embed, message, sessionId, {
            prompt,
            model,
            temperature,
          });

          await Telemetry.sendTelemetry("embed_sent_chat", {
            multiUserMode: multiUserMode(response),
            LLMSelection: process.env.LLM_PROVIDER || "openai",
            Embedder: process.env.EMBEDDING_ENGINE || "inherit",
            VectorDbSelection: process.env.VECTOR_DB || "lancedb",
          });
          response.end();
        } else {
          const { message } = reqBody(request);

          if (!sessionData.enterEmail) {
            console.log("Please enter your email");
            sessionData.enterEmail = true;
            storeSessionData(clientIp, sessionData);
            await promptUserForEmail(response);
            return;
          }

          if (
            !validateEmail(message) &&
            !sessionData.emailValidated &&
            !sessionData.sendOtp
          ) {
            console.log("Invalid email. Please enter a valid email");
            await informInvalidEmail(response);
            return;
          }

          if (
            !sessionData.sendOtp &&
            validateEmail(message) &&
            (await sendEmailOtp(request, response, message)) &&
            !sessionData.emailValidated
          ) {
            console.log("Please check OTP");
            sessionData.emailValidated = true;
            sessionData.sendOtp = true;
            storeSessionData(clientIp, sessionData);
            await promptUserForOTP(response);
            return;
          }

          if (
            sessionData.emailValidated &&
            sessionData.sendOtp &&
            !(await validateOtp(request, response, message))
          ) {
            console.log("OTP does not match");
            await informOTPMismatch(response);
            sessionData.enterEmail = false;
            storeSessionData(clientIp, sessionData);
            return;
          }

          if (
            sessionData.emailValidated &&
            sessionData.sendOtp &&
            (await validateOtp(request, response, message))
          ) {
            console.log("Verified OTP");
            // if (!otpMatched) {
            //     enterEmail = false;
            //     sessionData.emailValidated = false;
            //     sessionData.sendOtp = false;
            //     otpMatched = false;
            //     await verifiedOTP(response, finalToken);
            //     sessionData = {}; // Clear session data after OTP verification
            //     storeSessionData(clientIp, sessionData);
            // }
            await verifiedOTP(response, finalToken);
            sessionData = {}; // Clear session data after OTP verification
            storeSessionData(clientIp, sessionData);
          }
        }
      } catch (e) {
        console.error(e);
        writeResponseChunk(response, {
          id: uuidv4(),
          type: "abort",
          textResponse: null,
          close: true,
          error: e.message,
        });
        response.end();
      }
    }
  );

  app.get(
    "/embed/:embedId/:sessionId",
    [validEmbedConfig],
    async (request, response) => {
      try {
        const { sessionId } = request.params;
        const embed = response.locals.embedConfig;

        const history = await EmbedChats.forEmbedByUser(embed.id, sessionId);
        response.status(200).json({
          history: convertToChatHistory(history),
        });
      } catch (e) {
        console.log(e.message, e);
        response.sendStatus(500).end();
      }
    }
  );

  app.delete(
    "/embed/:embedId/:sessionId",
    [validEmbedConfig],
    async (request, response) => {
      try {
        const { sessionId } = request.params;
        const embed = response.locals.embedConfig;

        await EmbedChats.markHistoryInvalid(embed.id, sessionId);
        response.status(200).end();
      } catch (e) {
        console.log(e.message, e);
        response.sendStatus(500).end();
      }
    }
  );
}

function validateEmail(email) {
  return /\S+@\S+\.\S+/.test(email);
}
const sessionStore = {};

function generateSessionKey(ip, email) {
  return `${ip}:${email}`;
}

function storeSessionData(sessionKey, data) {
  sessionStore[sessionKey] = data;
}

function getSessionData(sessionKey) {
  return sessionStore[sessionKey];
}

async function sendEmailOtp(request, response, email) {
  try {
    const nodemailer = require("nodemailer");
    const speakeasy = require("speakeasy");
    const clientIp =
      request.headers["x-forwarded-for"] || request.connection.remoteAddress;
    finalSecret = "";

    const existingUser = await User._get({
      email: String(email),
    });
    if (existingUser) {
      const secret = speakeasy.generateSecret({
        length: 20,
      });

      function generateTOTP(secret) {
        const token = speakeasy.totp({
          secret: secret,
          encoding: "base32",
        });
        return token;
      }

      const otp = generateTOTP(secret.base32);
      const transporter = nodemailer.createTransport({
        name: "smtp.gmail.com",
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        logger: false,
        debug: true,
        sendMail: true,
        auth: {
          user: "woo.customercare@gmail.com",
          pass: "wisj fddu vnvs qild",
        },
      });

      const mailOptions = {
        from: "woo.customercare@gmail.com",
        to: email || "test123@yopmail.com",
        subject: "OTP",
        text: "One time password.",
        html: `<p>Dear User,</p> <p>Thank you for using <strong>anythingLLM</strong>. Your One-Time Password (OTP) is <strong>${otp}</strong>. Please use this OTP to complete your verification.</p> <p>This OTP is valid for 5 minutes.</p> <p>Thank you,<br>anythingLLM Team</p>`,
      };

      transporter.sendMail(mailOptions, async (error, info) => {
        if (error) {
          console.log("Error occurred:", error.message);
          return;
        }
        console.log("Email sent:", info.response);

        const userId = existingUser.id;

        const updatedUser = await prisma.users.update({
          where: {
            id: userId,
          },
          data: {
            otp_secret: otp,
          },
        });
        finalSecret = secret.base32;
        const sessionKey = generateSessionKey(clientIp, email);
        console.log("sessionkey email..", sessionKey);
        storeSessionData(sessionKey, {
          otpSecret: finalSecret,
          emailValidated: true,
          sendOtp: true,
        });
        console.log("Updated user:", updatedUser);
      });
      return true;
    } else {
      await invalidEmailExist(response);
      emailValidated = false;
      return false;
    }
  } catch (e) {
    console.error(e);
    writeResponseChunk(response, {
      id: uuidv4(),
      type: "abort",
      textResponse: null,
      close: true,
      error: e.message,
    });
    response.end();
  }
}

async function validateOtp(req, res, otp) {
  try {
    const clientIp =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const sessionKey = Object.keys(sessionStore).find((key) =>
      key.startsWith(clientIp)
    );
    if (!sessionKey) {
      await invalidOTP(res);
      return false;
    }

    const parts = sessionKey.split(":");
    const emaill = parts.pop();
    console.log("Extracted Email:", emaill, otp);

    const sessionData = getSessionData(sessionKey);
    console.log("sessionData..", sessionData);
    if (!sessionData) {
      await invalidOTP(res);
      return false;
    }
    const speakeasy = require("speakeasy");
    const otpSecret = sessionData.otpSecret;

    let existingUser = await User._get({
      email: emaill,
      otp_secret: otp,
    });
    console.log("existingUser...", existingUser);
    if (existingUser) {
      function verifyTOTP(secret, token) {
        const verified = speakeasy.totp.verify({
          secret: secret,
          encoding: "base32",
          token: token,
          window: 10,
        });
        return verified;
      }
    }
    if (existingUser) {
      const isVerified = verifyTOTP(otpSecret, otp);
      if (isVerified) {
        const newToken = createJWT(existingUser.id, req);
        finalToken = newToken;
        return true;
      } else {
        await otpExpired(res);
        sessionData.emailValidated = false;
        return false;
      }
    } else {
      await invalidOTP(res);
      return false;
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({
      error: e.message,
    });
  }
}
module.exports = {
  validateOtp,
}; //
module.exports = {
  embeddedEndpoints,
};
