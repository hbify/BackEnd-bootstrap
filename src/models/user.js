const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true,
    match: [/^(09|07)\d{8}$/, 'Please enter a valid phone number starting with 09 or 07']
  },
  contact: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Contact',
  },
  status: { 
    type: String, 
    enum: ['unverified', 'verified', 'pending'], default: 'unverified' 
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: {
    type: String
  },
  verificationTokenExpires: {
    type: Date
  }
}, { timestamps: true });

// Hash the user's password before saving to the database
userSchema.pre('save', async function(next) {
  const user = this;
  if (!user.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(user.password, salt);
  user.password = hash;
  next();
});

// Add a method to the user schema to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// it is used in passport local strategy
// Define an authenticate method to check the password when logging in
userSchema.statics.authenticate = async function (username, password) {
  const user = await this.findOne({ $or: [{ email: username }, { phone: username }] });
  if (!user) {
    // User not found
    return null;
  }
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    // Incorrect password
    return null;
  }
  // Successful login
  return user;
};

// user method to generate a token
userSchema.statics.generateVerificationToken = function() {
  const token = jwt.sign(
    {
      _id: this._id,
      email: this.email
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "1d"
    }
  );

  this.verificationToken = token;
  this.verificationTokenExpires = Date.now() + 86400000; // 24 hours

  return token;
};

module.exports = mongoose.model('User', userSchema);
