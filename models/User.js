const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const userSchema = new Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    isVerified: { type: Boolean, default: false }, // Indicates whether the email is verified
    verificationToken: { type: String } 
});

const User = mongoose.model('User', userSchema);

module.exports = User;
