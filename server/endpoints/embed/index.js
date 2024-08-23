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

app.post(
"/embed/:embedId/stream-chat",
[validEmbedConfig, setConnectionMeta, canRespond],
async (request, response) => {
try {
request.session.enterEmail = false;
const token = request.headers.authorization?.split(" ")[1];
const verify = verifyJWT(token, request);

if (token && verify) {
const embed = response.locals.embedConfig;
const {
sessionId,
message,
// optional keys for override of defaults if enabled.
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

if (!enterEmail) {
console.log("Please enter your email");
finalToken = "";
finalSecret = "";
enterEmail = true;
await promptUserForEmail(response);
console.log("Please enter your email console")
return;
}

if (!validateEmail(message) && !emailValidated && !sendOtp) {
console.log(
"Invalid email. Please enter a valid email",
enterEmail
);
await informInvalidEmail(response);
console.log("Please enter your email console")
return;
}

if (
!sendOtp &&
validateEmail(message) &&
(await sendEmailOtp(request, response, message)) &&
!emailValidated
) {
console.log("Please check OTP");
await promptUserForOTP(response);
emailValidated = true;
sendOtp = true;
return;
}

if (
emailValidated &&
sendOtp &&
!(await validateOtp(request, response, message))
) {
console.log("OTP does not match");
await informOTPMismatch(response);
enterEmail = false;
return;
}

if (
emailValidated &&
sendOtp &&
(await validateOtp(request, response, message))
) {
console.log("Verified OTP");
if (!otpMatched) {
enterEmail = false;
emailValidated = false;
sendOtp = false;
otpMatched = false;
await verifiedOTP(response, finalToken);
}
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

async function sendEmailOtp(request, response, email) {
try {
const nodemailer = require("nodemailer");
const speakeasy = require("speakeasy");
finalSecret = "";
const existingUser = await User._get({ email: String(email) });
if (existingUser) {
const secret = speakeasy.generateSecret({ length: 20 });

function generateTOTP(secret) {
const token = speakeasy.totp({
secret: secret,
encoding: "base32",
});
return token;
}

// Generate an OTP
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

// Email content
const mailOptions = {
from: "woo.customercare@gmail.com",
to: email || "test123@yopmail.com",
subject: "OTP",
text: "One time password.",
html: `<p>Dear User,</p> <p>Thank you for using <strong>anythingLLM</strong>. Your One-Time Password (OTP) is <strong>${otp}</strong>. Please use this OTP to complete your verification.</p> <p>This OTP is valid for 5 minutes.</p> <p>Thank you,<br>anythingLLM Team</p>`,
};

// Send email
transporter.sendMail(mailOptions, async (error, info) => {
if (error) {
console.log("Error occurred:", error.message);
return;
}
console.log("Email sent:", info.response);
const userId = existingUser.id;
const updatedUser = await prisma.users.update({
where: { id: userId },
data: { otp_secret: otp },
});
finalSecret = secret.base32;
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
const speakeasy = require("speakeasy");
let existingUser = await User._get({ otp_secret: otp });

// Function to verify a TOTP
function verifyTOTP(secret, token) {
const verified = speakeasy.totp.verify({
secret: secret,
encoding: "base32",
token: token,
// window: 1,
window: 10, // Set window to 10 to accommodate 5 minutes (5 * 60 / 30)

});
return verified;
}

// Verify the OTP
if (existingUser) {
const isVerified = verifyTOTP(finalSecret, otp);
if (isVerified) {
const token = createJWT(existingUser.id, req);
finalToken = token;
// finalSecret = "";
return true;
} else {
await otpExpired(res);
emailValidated = false;
return false;
}
} else {
await invalidOTP(res);
return false;
}
} catch (e) {
console.error(e);
}
}
module.exports = { embeddedEndpoints };
