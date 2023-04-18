const nodemailer = require('nodemailer');

const sendVerificationLink = async (user) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: user.email,
    subject: 'Verification Link',
    html: `Please click this link to verify your account: <a href="${process.env.BASE_URL}/users/verify/${user.verificationToken}">Verify</a>`,
  };

  await transporter.sendMail(mailOptions);
}

module.exports = {
  sendVerificationLink,
};
