const path = require('node:path');
const fs = require('node:fs');
const { v4: uuidv4 } = require("uuid");
const { parentPort } = require('node:worker_threads');
const documentsPath =
  process.env.NODE_ENV === "development"
    ? path.resolve(__dirname, `../../storage/documents`)
    : path.resolve(process.env.STORAGE_DIR, `documents`);

const {
      convertToChatHistory,
      writeResponseChunk,
      clientAbortedHandler,
    } = require("../../utils/helpers/chat/responses");
function log(stringContent = '') {
  if (parentPort) parentPort.postMessage(stringContent);
  else console.log(`parentPort is undefined. Debug: ${stringContent}`)
}

function conclude() {
  if (parentPort) parentPort.postMessage('done');
  else process.exit(0);
}

function updateSourceDocument(docPath = null, jsonContent = {}) {
  const destinationFilePath = path.resolve(documentsPath, docPath);
  fs.writeFileSync(destinationFilePath, JSON.stringify(jsonContent, null, 4), {
    encoding: "utf-8",
  });
}


async function promptUserForEmail(response) {
  const simulatedStream = [
    { choices: [{ delta: { content: "Please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " your" } }] },
    { choices: [{ delta: { content: " email" } }] },
    { choices: [{ delta: { content: "!" } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ];
  await simulateStream(response, simulatedStream);
}

async function informInvalidEmail(response) {
  // Simulated message for invalid email format
  await simulateStream(response, [
    { choices: [{ delta: { content: "Invalid" } }] },
    { choices: [{ delta: { content: " email" } }] },
    { choices: [{ delta: { content: " format" } }] },
    { choices: [{ delta: { content: " ." } }] },
    { choices: [{ delta: { content: " Please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " a" } }] },
    { choices: [{ delta: { content: " valid" } }] },
    { choices: [{ delta: { content: " email" } }] },
    { choices: [{ delta: { content: " address" } }] },
    { choices: [{ delta: { content: " ." } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}

async function invalidEmailExist(response) {
  // Simulated message for invalid email format
  await simulateStream(response, [
    { choices: [{ delta: { content: "Email" } }] },
    { choices: [{ delta: { content: " does" } }] },
    { choices: [{ delta: { content: " not" } }] },
    { choices: [{ delta: { content: " exist" } }] },
    { choices: [{ delta: { content: " ." } }] },
    { choices: [{ delta: { content: " Please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " a" } }] },
    { choices: [{ delta: { content: " valid" } }] },
    { choices: [{ delta: { content: " email" } }] },
    { choices: [{ delta: { content: " address" } }] },
    { choices: [{ delta: { content: " ." } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}

async function promptUserForOTP(response) {
  // Simulated prompt for user to enter OTP
  await simulateStream(response, [
    { choices: [{ delta: { content: "Please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " the" } }] },
    { choices: [{ delta: { content: " 6" } }] },
    { choices: [{ delta: { content: " -" } }] },
    { choices: [{ delta: { content: " digit" } }] },
    { choices: [{ delta: { content: " OTP" } }] },
    { choices: [{ delta: { content: " ." } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}

async function informOTPMismatch(response) {
  // Simulated message for OTP mismatch
  await simulateStream(response, [
    { choices: [{ delta: { content: "OTP" } }] },
    { choices: [{ delta: { content: " entered" } }] },
    { choices: [{ delta: { content: " did" } }] },
    { choices: [{ delta: { content: " not" } }] },
    { choices: [{ delta: { content: " match" } }] },
    { choices: [{ delta: { content: " ." } }] },
    { choices: [{ delta: { content: " Please" } }] },
    { choices: [{ delta: { content: " try" } }] },
    { choices: [{ delta: { content: " again" } }] },
    { choices: [{ delta: { content: " !" } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}

async function invalidOTP(response) {
  // Simulated prompt for user to enter OTP
  await simulateStream(response, [
    { choices: [{ delta: { content: "Invalid" } }] },
    { choices: [{ delta: { content: " OTP" } }] },
    { choices: [{ delta: { content: " please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " valid" } }] },
    { choices: [{ delta: { content: " OTP" } }] },
    { choices: [{ delta: { content: " ." } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}
async function verifiedOTP(response ,finalToken) {
  // Simulated message for OTP mismatch
  await simulateStream(response, [
    { choices: [{ delta: { content: "You" } }] },
    { choices: [{ delta: { content: " have" } }] },
    { choices: [{ delta: { content: " to" } }] },
    { choices: [{ delta: { content: " verified" } }] },
    { choices: [{ delta: { content: " !" } }] },
    { choices: [{ delta: { content: " ." } }] },
    { choices: [{ delta: { content: " How" } }] },
    { choices: [{ delta: { content: " can" } }] },
    { choices: [{ delta: { content: " I" } }] },
    { choices: [{ delta: { content: " assist" } }] },
    { choices: [{ delta: { content: " you" } }] },
    { choices: [{ delta: { content: " today" } }] },
    { choices: [{ delta: { content: "?" } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ] , finalToken);
}
async function otpExpired(response) {
  // Simulated message for maximum attempts reached
  await simulateStream(response, [
    { choices: [{ delta: { content: "Your" } }] },
    { choices: [{ delta: { content: " otp" } }] },
    { choices: [{ delta: { content: " has" } }] },
    { choices: [{ delta: { content: " expired" } }] },
    { choices: [{ delta: { content: " ." } }] },
    { choices: [{ delta: { content: " Please" } }] },
    { choices: [{ delta: { content: " enter" } }] },
    { choices: [{ delta: { content: " email" } }] },
    { choices: [{ delta: { content: " again" } }] },
    { choices: [{ delta: { content: " ." } }] },
    // Add more simulated data as needed
    { index: 0, delta: {}, logprobs: null, finish_reason: "stop" },
  ]);
}

async function simulateStream(response, simulatedStream , finalToken="") {
  return new Promise(async (resolve) => {
    const uuid = uuidv4();
    let fullText = "";
    const handleAbort = () => clientAbortedHandler(resolve, fullText);
    response.on("close", handleAbort);
    // console.log('responseinner',response);
    for await (const chunk of simulatedStream) {
      const message = chunk?.choices?.[0];
      const text = message?.delta?.content;
      if (text) {
        fullText += text;
        writeResponseChunk(response, {
          uuid,
          anyThingToken: finalToken ? finalToken : "",
          sources: [],
          type: "textResponseChunk",
          textResponse: text,
          close: false,
          error: false,
        });
      }

      if (
        message?.hasOwnProperty("finish_reason") && // Got valid message and it is an object with finish_reason
        message.finish_reason !== "" &&
        message.finish_reason !== null
      ) {
        writeResponseChunk(response, {
          uuid,
          sources,
          type: "textResponseChunk",
          textResponse: "",
          close: true,
          error: false,
        });
        response.removeListener("close", handleAbort);
        resolve(fullText);
        break;
      }

    }
    response.end();
  });
}


module.exports = {
  log,
  conclude,
  updateSourceDocument,
  promptUserForEmail,
  informInvalidEmail,
  invalidEmailExist,
  promptUserForOTP,
  informOTPMismatch,
  verifiedOTP,
  otpExpired,
  invalidOTP
}