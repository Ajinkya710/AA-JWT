const express = require("express");
require("dotenv").config();
const app = express();
mongoose = require("mongoose"),
userRoutes = require("./routes/user");

try {
    mongoose.connect("mongodb://localhost:27017/usersdb", {
      useUnifiedTopology: true,
      useNewUrlParser: true
    });
    console.log("connected to db");
  } catch (error) {
    console.log(error);
  }
  process.on('unhandledRejection', error => {
    console.log('unhandledRejection', error.message);
  });

// parse requests of content-type - application/json
app.use(express.json());
// parse requests of content-type - application/x-www-form-urlencoded
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(userRoutes);


//setup server to listen on port 8080
app.listen(process.env.PORT || 8080, () => {
  console.log("Server is live on port 8080");
});
