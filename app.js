require('dotenv').config();
const  express = require('express');
const  path = require('path');
const  cookieParser = require('cookie-parser');
const session = require('express-session');
//const  logger = require('morgan');
const mongoose = require('mongoose');
const config = require('./src/utils/config');
const cors = require('cors');
const userRouter = require('./src/routes/user');
const middlewares = require('./src/utils/middlewares');
const logger = require('./src/utils/loggers');
const passport = require('passport');
const passportConfig = require('./src/utils/passport');
require('./src/utils/db');


//const  indexRouter = require('./routes/index');
//const  usersRouter = require('./routes/users');

const  app = express();

//app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//app.use('/', indexRouter);
//app.use('/users', usersRouter);

mongoose.set('strictQuery', false);
/*
logger.info('connecting to', db.uri)

mongoose.connect(db.uri, db.options)
  .then(() => {
    logger.info('connected to MongoDB')
  })
  .catch((error) => {
    logger.error('error connecting to MongoDB:', error.message)
  })
*/
app.use(cors())
app.use(express.static('build'))
app.use(express.json())
app.use(middlewares.requestLogger)

// Passport middlewares
app.use(passport.initialize());
//app.use(passport.session());

app.use('/api/user', userRouter)

app.use(middlewares.unknownEndpoint)
app.use(middlewares.errorHandler)

module.exports = app