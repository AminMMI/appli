const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const { SECRET } = require("../config");

const User = require("../models/user");

function getToken(req) {
  let token = ExtractJwt.fromAuthHeaderWithScheme("Bearer")(req);
  return token;
}

module.exports = function (app) {
  const opts = {};
  opts.jwtFromRequest = getToken;
  opts.secretOrKey = SECRET;

  passport.use(
    "user",
    new JwtStrategy(opts, async function (jwtPayload, done) {
      try {
        const user = await User.findOne({ _id: jwtPayload._id });
        if (user) return done(null, user);
      } catch (error) {
        console.log("🚀 ~ JwtStrategy ~ error:", error);
      }
      return done(null, false);
    })
  );

  passport.use(
    "admin",
    new JwtStrategy(opts, async function (jwtPayload, done) {
      return done(null, { _id: jwtPayload._id, _type: "admin" });
    })
  );

  app.use(passport.initialize());
};
