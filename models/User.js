const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    min: 7,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
    max: 1024,
    min: 8,
  },
});

userSchema.methods.validPassword = function (pwd) {
  return this.password === pwd;
};

module.exports = mongoose.model("User", userSchema);
