import User from "../users/users.models.js";
import asyncHandler from "express-async-handler";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { promisify } from 'util';


const createSendToken = (user, statusCode, req, res) => {
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET,  {
    expiresIn: 10 * 24 * 60 * 60 // Expires in 10 days
  });

  res.cookie('access_token', token, {
    expires: new Date(
      Date.now() + 10 * 24 * 60 * 60 * 1000 // expires in 10days
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https'
  });

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    success: true,
    token,
    data: user
  });
};

const registerUser = asyncHandler(async (req, res) => {
  const email = req.body.email.toLowerCase();
  const findUser = await User.findOne({ email });

  if (!findUser) {
    const newUser = await User.create({
      ...req.body,
      email: email,
    });
    try {
      const { password, ...userWithoutPassword } = newUser._doc;
      return res.status(201).json({
        success: true,
        data: userWithoutPassword
      });
    } catch (error) {
      return res
        .status(500)
        .json({
          success: false,
          error: {
            code: 500,
            message: "Unable to sign up, please try again" 
          }
        });
    }
  } else {
    res.status(400).json({ error: "User already exists" });
  }
});

const loginUser = asyncHandler(async (req, res) => {
  try {
    const email = req.body.email.toLowerCase();
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Incorrect email or password!" });
    }
    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect) {
      return res.status(401).json("Wrong password or email!");
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    const { password, ...otherDetails } = user._doc;
    res
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .status(200)
      .json({ user: { ...otherDetails } });
  } catch (error) {
    console.error(error);
  }
});

const logoutUser = asyncHandler((req, res) => {
  res
    .clearCookie("access_token")
    .status(200)
    .json({ message: "Logged out successfully" });
});


const protect = asyncHandler(async (req, res, next) => {
  let token;
  
  if (req.cookies.access_token) {
    token = req.cookies.access_token;
  }

  if (!token) {
    res.status(401).json({
      success: false,
      error: {
        code: 401,
        message: 'You are not logged in! Please log in to get access.'
      }
    });
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    res.status(401).json({
      success: false,
      error: {
        code: 401,
        message: 'The user belonging to this token does no longer exist.'
      }
    });
  }
   // Check if user changed password after the token was issued
  // if (currentUser.changedPasswordAfter(decoded.iat)) {
  //   return next(
  //     new AppError('User recently changed password! Please log in again.', 401)
  //   );
  // }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  res.locals.user = currentUser;
  next();

});

const updatePassword = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user.id).select('+password');

  const isOldPasswordCorrect = await bcrypt.compare(
    req.body.oldPassword,
    user.password
  );
  if (!isOldPasswordCorrect) {
    return res.status(401).json({
      success: false,
      error:{
        code: 401,
        message: 'Your oldPassword is wrong.'
    }
    });
  }

  user.password = req.body.newPassword;
  await user.save();

  createSendToken(user, 200, req, res);
});

export { registerUser, loginUser, logoutUser, protect, updatePassword };
