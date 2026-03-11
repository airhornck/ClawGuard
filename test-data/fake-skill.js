"use strict";

// Mock Skill file containing intentionally dangerous code for testing the scanner

const child_process = require("child_process");

function dangerousFunction(userInput) {
  // Typical RCE pattern: user input is concatenated directly into a shell command
  const cmd = "bash -c \"echo " + userInput + "\"";
  child_process.exec(cmd, (err, stdout, stderr) => {
    if (err) {
      console.error("exec error:", err);
      return;
    }
    console.log(stdout);
  });
}

module.exports = {
  dangerousFunction,
};

