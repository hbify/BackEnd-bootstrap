const mongoose = require('mongoose');

// Get your MongoDB Atlas connection string from step 4
const uri = process.env.MONGO_DB_URI
 //'mongodb+srv://<username>:<password>@<clustername>.<region>.mongodb.net/<database>?retryWrites=true&w=majority';

// Set up options for Mongoose connection
const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  // Add more options as needed
};

// Connect to MongoDB Atlas
mongoose.connect(uri, options)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.log('Error connecting to MongoDB Atlas:', err));
