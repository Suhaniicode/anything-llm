process.env.NODE_ENV === "development"
  ? require("dotenv").config({ path: `.env.${process.env.NODE_ENV}` })
  : require("dotenv").config();
const JWT = require("jsonwebtoken");
const uuid = require("uuid");
const { User } = require("../../models/user");
const { jsonrepair } = require("jsonrepair");
const extract = require("extract-json-from-string");
const sessions = {};
function reqBody(request) {
  return typeof request.body === "string"
    ? JSON.parse(request.body)
    : request.body;
}

function queryParams(request) {
  return request.query;
}

function makeJWT(info = {}, expiry = "30d") {
  if (!process.env.JWT_SECRET)
    throw new Error("Cannot create JWT as JWT_SECRET is unset.");
  return JWT.sign(info, process.env.JWT_SECRET, { expiresIn: expiry });
}

// Note: Only valid for finding users in multi-user mode
// as single-user mode with password is not a "user"
async function userFromSession(request, response = null) {
  if (!!response && !!response.locals?.user) {
    return response.locals.user;
  }

  const auth = request.header("Authorization");
  const token = auth ? auth.split(" ")[1] : null;

  if (!token) {
    return null;
  }

  const valid = decodeJWT(token);
  if (!valid || !valid.id) {
    return null;
  }

  const user = await User.get({ id: valid.id });
  return user;
}

function decodeJWT(jwtToken) {
  try {
    return JWT.verify(jwtToken, process.env.JWT_SECRET);
  } catch {}
  return { p: null, id: null, username: null };
}

function multiUserMode(response) {
  return response?.locals?.multiUserMode;
}

function parseAuthHeader(headerValue = null, apiKey = null) {
  if (headerValue === null || apiKey === null) return {};
  if (headerValue === "Authorization")
    return { Authorization: `Bearer ${apiKey}` };
  return { [headerValue]: apiKey };
}

function safeJsonParse(jsonString, fallback = null) {
  try {
    return JSON.parse(jsonString);
  } catch {}

  if (jsonString?.startsWith("[") || jsonString?.startsWith("{")) {
    try {
      const repairedJson = jsonrepair(jsonString);
      return JSON.parse(repairedJson);
    } catch {}
  }

  try {
    return extract(jsonString)[0];
  } catch {}

  return fallback;
}

function isValidUrl(urlString = "") {
  try {
    const url = new URL(urlString);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    return true;
  } catch (e) {}
  return false;
}

function toValidNumber(number = null, fallback = null) {
  if (isNaN(Number(number))) return fallback;
  return Number(number);
}

function createJWT(userId, req) {
  const sessionId = uuid.v4();

  const payload = {
    userId,
    sessionId,
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour expiration
    ip: req.ip,
    userAgent: req.get("User-Agent"),
  };
  const token = JWT.sign(payload, process.env.JWT_SECRET);
  sessions[userId] = sessionId;
  return token;
}

function verifyJWT(token, req) {
  try {
    if (!token) {
      return res.status(403).send("Token required");
    }

    const payload = JWT.verify(token, process.env.JWT_SECRET);
    if (payload.ip !== req.ip || payload.userAgent !== req.get("User-Agent")) {
      return res.status(403).send("Invalid token");
    }
    const { userId, sessionId } = payload;
    return sessions[userId] === sessionId;
  } catch (err) {
    return false;
  }
}

module.exports = {
  reqBody,
  multiUserMode,
  queryParams,
  makeJWT,
  decodeJWT,
  userFromSession,
  parseAuthHeader,
  safeJsonParse,
  isValidUrl,
  toValidNumber,
  createJWT,
  verifyJWT,
};
