const express = require('express');
const router = express.Router();
const passport = require('passport');
const UserController = require('../controllers/user');

// Create user
router.post('/', UserController.createUser);

// Get all users
router.get('/', passport.authenticate('jwt', { session: false }), UserController.getAllUsers);

// Get user by ID
router.get('/:userId', passport.authenticate('jwt', { session: false }), UserController.getUserById);

// Update user by ID
router.put('/:userId', passport.authenticate('jwt', { session: false }), UserController.updateUserById);

// Delete user by ID
router.delete('/:userId', passport.authenticate('jwt', { session: false }), UserController.deleteUserById);

// Search users by any field given by req.body
router.post('/search', passport.authenticate('jwt', { session: false }), UserController.searchUser);


// Password reset request
router.post('/password/reset', UserController.requestPasswordReset);

// Password reset confirmation
router.post('/password/reset/confirm', UserController.confirmPasswordReset);
// Login
router.post('/login', UserController.login);

// Logout
router.get('/logout', passport.authenticate('jwt', { session: false }), UserController.logout);

//verify user
router.put('/verify/:token', UserController.verifyUser);
module.exports = router;
