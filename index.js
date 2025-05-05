
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = require("./databaseConnection.js");  


const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

app.use(express.static(__dirname + "/public"));


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));



/* === Homepage === */
app.get("/", (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello, ${req.session.username}!</h1>
            <a href='/members'><button>Go to Members Area</button></a> |
            <a href='/logout'><button>Logout</button></a>
        `);
    } else {
        res.send(`
            <h1>Welcome to the Website</h1>
            <a href='/signup'><button>Sign Up</button></a> 
            <br> <a href='/login'><button>Log In</button></a>
        `);
    }
});


/* === Signup Page === */
app.get("/signup", (req, res) => {
    res.send(`
        <h2>Sign Up</h2>
        <form action="/signupSubmit" method="POST">
            <input type="text" name="name" placeholder="Name" required />
           <br> <input type="email" name="email" placeholder="Email" required />
            <br><input type="password" name="password" placeholder="Password" required />
            <br><button type="submit">Sign Up</button>
        </form>
    `);
});

app.post("/signupSubmit", async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(20).required(),
    });

    const { error } = schema.validate(req.body);
    if (error) return res.send(`Error: ${error.details[0].message} <a href='/signup'><button>Try Again</button></a>`);

    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    await userCollection.insertOne({ name: req.body.name, email: req.body.email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.username = req.body.name;
    res.redirect("/");
});


/* === Login Page === */
app.get("/login", (req, res) => {
    res.send(`
        <h2>Log In</h2>
        <form action="/loginSubmit" method="POST">
            <input type="email" name="email" placeholder="Email" required />
          <br>  <input type="password" name="password" placeholder="Password" required />
          <br>  <button type="submit">Login</button>
        </form>
    `);
});

app.post("/loginSubmit", async (req, res) => {
    const user = await userCollection.findOne({ email: req.body.email });
    if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
        return res.send("Invalid email or password. <a href='/login'>Try Again</a>");
    }

    req.session.authenticated = true;
    req.session.username = user.name;
    res.redirect("/");
});



/* === Members Page === */
app.get("/members", (req, res) => {
    if (!req.session.authenticated) return res.redirect("/");

    const images = ["image1.jpg", "image2.jpg", "image3.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h2>Hello, ${req.session.username}!</h2>
        <img src="/${randomImage}" alt="Random Image" style="width:300px; height:auto;">
        <br> <a href="/logout"> <button>Sign Out</button> </a>
    `);
});


/* === Logout === */
app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});


/* === NoSQL Injection Protection Example === */
app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});



app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 