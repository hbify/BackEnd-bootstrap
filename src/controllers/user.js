const User = require('../models/user');
const jwt = require('jsonwebtoken');
//const config = require('../config');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

exports.createUser = async (req, res, next) => {
  try {
    const { phone, email } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ phone }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'phone or email already exists.' });
    }

    // Create user
    const user = new User(req.body);
    await user.save();

    res.status(201).json({ message: 'User created successfully.' });
  } catch (err) {
    next(err);
  }
};

exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find({}, '-password');
    res.status(200).json(users);
  } catch (err) {
    next(err);
  }
};

exports.getUserById = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId, '-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.status(200).json(user);
  } catch (err) {
    next(err);
    
  }
};

exports.updateUserById = (req, res, next) => {
    const userId = req.params.userId;
    const updateOps = req.body;

   
  User.findByIdAndUpdate(userId, updateOps, { new: true, omitUndefined: true, password: 0 })
    .then((updatedUser) => {
      console.log('User updated:', updatedUser);
      res.json(updatedUser);
    })
    .catch((err) => {
      console.error(err);
      return next(err);
    });

  };
  

exports.deleteUserById = async (req, res, next) => {
    try {
      const userId = req.params.userId;
      const user = await User.findById(userId);
      if (!user) {
        const error = new Error('Could not find user');
        error.statusCode = 404;
        throw error;
      }
      const result = await User.deleteOne({ _id: userId });
      res.status(200).json({
        message: 'User deleted successfully!',
        userId: result._id,
      });
    } catch (error) {
      next(error);
    }
  };

  exports.searchUser = async (req, res, next) => {
    try {
        const users = await User.find(req.body, '-password');
        res.status(200).json(users);
      } catch (err) {
        next(err);
      }
  };

// Request password reset
exports.requestPasswordReset = async (req, res, next) => {
  try {
    // Find user by email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Update user reset token
    user.resetPasswordToken = resetToken;
    await user.save();

    // Send reset email
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const resetUrl = `${process.env.APP_URL}/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>Hello ${user.email},</p>
        <p>You have requested a password reset for your account.</p>
        <p>Please click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
      `,
    });

    return res.status(200).json({ message: 'Password reset link sent' });
  } catch (error) {
    next(error);
  }
};

// Confirm password reset
exports.confirmPasswordReset = async (req, res, next) => {
  try {
    // Decode reset token
    const decodedToken = jwt.verify(req.body.token, process.env.JWT_SECRET);

    // Find user by email and reset token
    const user = await User.findOne({ email: decodedToken.email, resetPasswordToken: req.body.token });
    if (!user) {
      return res.status(404).json({ message: 'Invalid token' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Update user password and reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    await user.save();

    return res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    next(error);
  }
};

/*
cexports.login = async (req, res, next) => {
  const { phone, password } = req.body;

  try {
    // Find user with phone
    const user = await User.findOne({ phone });

    // If user not found
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Compare password
    const isMatch = await comparePassword(password, user.password);

    // If password doesn't match
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate and sign JWT token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Set JWT token as cookie
    res.cookie('token', token, { httpOnly: true });

    // Return user data and token
    return res.status(200).json({ user, token });
  } catch (err) {
    return next(err);
  }
};
*/

exports.login = async (req, res, next) => {
  const { username, password } = req.body;

  try {

    const user = await User.authenticate(username, password);
    if (!user) {
      return res.status(404).json({ message: 'Incorrect username or password.' });
    }
    // If the passwords match, generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);

    // Return the token and the user's info
    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
      },
    });
  } catch (err) {
    next(err);
  }
};


exports.logout = async (req, res, next) => {
  try {
    // Clear JWT token cookie
    res.clearCookie('token');
    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    return next(err);
  }
};