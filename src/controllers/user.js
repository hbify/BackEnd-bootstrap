const User = require('../models/user');
const jwt = require('jsonwebtoken');
//const config = require('../config');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const { sendVerificationLink } = require('../services/verificationService');


exports.createUser = async (req, res, next) => {
  try {
    const { phone, email } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ phone }, { email }] });
    if (existingUser) {
      return res.status(409).json({ message: 'phone or email already exists.' });
    }

    // Create user
    const user = new User({ ...req.body, verificationToken: User.generateVerificationToken()});
    await user.save();

    await sendVerificationLink(user);
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
exports.login = async (req, res, next) => {
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

// sends verification link to users email address
/*
exports.sendVerificationLink = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // generate a unique verification token
    const token = user.generateVerificationToken();
    await user.save();

    // send the verification email
    const transporter = nodemailer.createTransport({
      // your email service configuration
    });

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: user.email,
      subject: 'Account Verification',
      html: `
        <p>Hello ${user.name},</p>
        <p>Please click the following link to verify your account:</p>
        <a href="${process.env.BASE_URL}/api/users/verify/${token}">Verify my account</a>
      `
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Failed to send verification email' });
      }

      return res.status(200).json({ message: 'Verification email sent' });
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Failed to send verification email' });
  }
};
*/

// function to verify a user when the verification link is clicked
exports.verifyUser = async (req, res) => {
  try {
    const token = req.params.token; // Get the verification token from the URL params
    const user = await User.findOne({ verificationToken: token }); // Find the user with the matching verification token

    if (!user) {
      return res.status(404).json({ success: false, message: 'Invalid verification token' }); // Return an error response if the user is not found
    }

    if (user.isVerified) {
      return res.status(400).json({ success: false, message: 'This user has already been verified' }); // Return an error response if the user has already been verified
    }

    user.isVerified = true; // Set the user's `isVerified` flag to true
    user.status = 'verified'; // Set the user's `status` flag to verified
    user.verificationToken = undefined; // Remove the verification token
    await user.save(); // Save the updated user document

    return res.status(200).json({ success: true, message: 'User has been successfully verified' }); // Return a success response
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: 'Server error' }); // Return a server error response if an error occurs
  }
};

