const mongoose = require("mongoose");

// MongoDbConnection.
const mongoDbConnection = () => {
  try {
    mongoose.connect(process.env.MONGO_STRING);
    console.log(`MongoDbConnection is successful`.bgBlue.black);
  } catch (error) {
    console.log(`${error.message}`.bgBlue.black);
  }
};

// Export.
module.exports = mongoDbConnection;
