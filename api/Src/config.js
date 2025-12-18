const ENVIRONMENT = getEnvironment();
const MONGODB_ENDPOINT = process.env.MONGODB_ENDPOINT;
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || "dev-only-secret";

module.exports = {
  PORT,
  MONGODB_ENDPOINT,
  SECRET,
  ENVIRONMENT,
};

function getEnvironment() {
  return process.env.ENVIRONMENT || "development";
}