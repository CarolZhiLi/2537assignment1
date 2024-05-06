require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;
const expireTime = 1 * 60 * 60 * 1000;

const app = express();
const port = process.env.PORT || 3000;
const Joi = require("joi");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

console.log(process.env.NODE_SESSION_SECRET);
require("./utils.js");
var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

//Middleware to parse the body
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));


app.get('/',(req,res) => {
    var html = `
        <button onclick='window.location.href = "/signup"'>Sign up</button>
        <button onclick='window.location.href = "/login"'>Log in</button>
    `;
    res.send(html);
});

app.get('/signup/', (req,res) => {
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
        <input name='username' type='text' placeholder='name'>
        <input name='email' type='email' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/signupSubmit', async(req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    var html = "";
    if (!username) {
        html += "<br> username is required"
    }
    if (!email) {
        html += "<br> email is required"
    }
    if (!password) {
        html += "<br> password is required"
    }
    if(!username || !email || !password) {
        html += '<br><a href="/signup">Try again</a>';
        return res.send(html);
    }
    
    const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().required(),
			password: Joi.string().min(8).required()
		});
    const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup/");
	   return;
   }
    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Added user");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
});

app.get('/login/', (req,res) => {
    var html = `
    log in
    <form action='/loginSubmit' method='post'>
        <input name='email' type='email' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
            email: Joi.string().required(),
			password: Joi.string().min(8).required()
		});
	const validationResult = schema.validate({email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   return res.send(`Invalid email/password combination<br><a href="/login/">Try again</a>`);
	}
    
	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();   
	console.log(result);
    console.log(result[0].username);

	if (result.length != 1) {
		console.log("user not found");
		return res.send(`Invalid email/password combination<br><a href="/login/">Try again</a>`);
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;
        
		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		return res.send(`Invalid email/password combination<br><a href="/login/">Try again</a>`);
	}
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    const images = ['/image1.jpeg', '/image2.jpeg', '/image3.jpg'];
    const randomImage = images[Math.floor(Math.random()*images.length)];
    const name = req.session.username;
    console.log(name);
    res.send(`Hello, ${name}. <br>
        <img src="${randomImage}" alt="Image" /> <br>
        <button onclick='window.location.href = "/logout"'>Sign out</button>
    `);
});



app.get('/logout', (req,res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));


app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 