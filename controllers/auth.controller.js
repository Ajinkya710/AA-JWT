const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/user");

exports.signup = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 8);

    const user = new User({
      fullName: req.body.fullName,
      email: req.body.email,
      role: req.body.role,
      password: hashedPassword
    });

    await user.save();

    res.status(200).send({
      message: "User Registered successfully"
    });
  } catch (error) {
    res.status(500).send({
      message: error.message || "An error occurred while registering the user."
    });
  }
};

exports.signin = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).send({
        message: "User Not found."
      });
    }

    const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

    if (!passwordIsValid) {
      return res.status(401).send({
        accessToken: null,
        message: "Invalid Password!"
      });
    }

    const token = jwt.sign({ id: user.id }, process.env.API_SECRET, {
      expiresIn: 86400
    });

    res.status(200).send({
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName
      },
      message: "Login successful",
      accessToken: token
    });
  } catch (error) {
    res.status(500).send({
      message: error.message || "An error occurred while signing in."
    });
  }
};
