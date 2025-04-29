require('dotenv').config();

console.log("Loaded environment variables:", process.env);

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_database = process.env.MONGODB_DATABASE;


console.log("Loaded database name:", mongodb_database);

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority&appName=Cluster0`;
var database = new MongoClient(atlasURI, {});
module.exports = {database};