const passport = require('passport');
const  LocalStrategy = require('passport-local');
const  User = require('./../models/user')
const  JwtStrategy = require('passport-jwt').Strategy;
const  ExtractJwt = require('passport-jwt').ExtractJwt;
const  opts = {}

opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET;
console.log('====================================');
console.log(opts);
console.log('====================================');
passport.use(new JwtStrategy(opts, async (payload, done) => {
  try {
    const user = await User.findOne({ _id: payload.userId }); // Use await with findOne() instead of callback
    console.log('====================================');
    console.log("jwt payload ", payload);
    console.log('====================================');
    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (err) {
    return done(err, false);
  }
}));

passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
  }, async function(username, password, done) {
    try {
      const user = await User.authenticate(username, password);
      if (!user) {
        return done(null, false, { message: 'Incorrect username or password.' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));
