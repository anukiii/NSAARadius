const express = require('express')
const session = require('express-session')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)
const cookieParser = require('cookie-parser')
const scryptMcf = require('scrypt-mcf')
const sqlite3 = require("sqlite3")
const axios = require('axios')

const { Issuer } = require('openid-client')

const Client = require('node-radius-client');
const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');

const OpenIDConnectStrategy = require('openid-client').Strategy

const { hash, verify } = require('scrypt-mcf');

const dotenv = require('dotenv')
dotenv.config()

async function main () {

  radius = false;
  const app = express()
  const port = 3000

  app.use(logger('dev'))
  app.use(session({
      //secret used to sign session cookie
      secret: require('crypto').randomBytes(32).toString('base64url'), 
      //says not to save the session to the session store 
      resave: false,
      //dont save uninitialised sessions 
      saveUninitialized: false
  }))
  app.use(cookieParser())

  //########################  DATABASE CONNECTION ################################# #################################################################################

  const db = new sqlite3.Database('./users.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) return console.error(err.message);

    console.log("Connection successful");
  });

  //########################  DATABASE CONNECTION ################################### ###################################################################################


  // ####################### RADIUS STRATEGY ########################################


  passport.use('local-radius', new LocalStrategy(
    {
      username: 'username',
      password: 'password',
      session: false
    },
    function (username, password, done) {
      const client = new Client({
        host: '127.0.0.1',
        dictionaries: [
            file,
        ],
    });
  
    client.accessRequest({
        secret: 'testing123',
        attributes: [
            [attributes.USER_NAME, username],
            [attributes.USER_PASSWORD, password],
        ],
    }).then((result) => {
        console.log('result', result);
        const user = {
          username: username
        };
        
          return done(null, user);

    }).catch((error) => {
        console.log('error', error);
        return done(null, false);
    });
    }
  ))

  // ####################### RADIUS STRATEGY ########################################

  // ####################### PASSWORD STRATEGY ######################################

  passport.use('username-password', new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      session: false
    },
    function (username, password, done) {
      sql = `SELECT * FROM user WHERE username = ?`;
      
    db.get(sql, [username], (err, row) => {
      
          if (err) { return console.error(err.message) };
          if (!row) {return console.log("No row!");};
          
          
          
          async function verifyPassword() {
          
          passwordMatch = await verify(password, row.password);
          
            if (passwordMatch) {
              return done(null, row);
            } else {
              return done(null, false);
            }
          }
          
          verifyPassword();
        });
    }
  ))

  // ####################### PASSWORD STRATEGY #####################################

  // ####################### COOKIE STRATEGY #####################################

  passport.use('jwtCookie', new JwtStrategy(
    {
      jwtFromRequest: (req) => {
        if (req && req.cookies) { return req.cookies.jwt }
        return null
      },
      secretOrKey: jwtSecret
    },
    function (jwtPayload, done) {
    
      const { expiration, sub } = jwtPayload

        if (Date.now() > expiration) {
            done('Unauthorized', false)
        }
        
        console.log("Print: " + sub);

        done(null, jwtPayload)
    
      /*sql = `SELECT * FROM user WHERE username = ?`;
      
      db.get(sql, [jwtPayload.sub], (err, row) => {
        if (err) { console.error(err.message) };
          if (!row) { return done(null, false) };
          
          return done(null, row);
      });*/
      
      
    }
  ))

  // ####################### COOKIE STRATEGY #####################################

  // ######################## OPENID CONNECT STRATEGY #############################

    // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
  const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

    // 2. Setup an OIDC client/relying party.
  const oidcClient = new oidcIssuer.Client({
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      redirect_uris: [process.env.OIDC_CALLBACK_URL],
      response_types: ['code'] //token for an authorisation code grant
  })

  // 3. Configure the strategy.
  passport.use('oidc', new OpenIDConnectStrategy({
      client: oidcClient,
      usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
    }, (tokenSet, userInfo, done) => {
      console.log(tokenSet, userInfo)
      console.log(userInfo.email)
      if (tokenSet === undefined || userInfo === undefined) {
        return done('no tokenSet or userInfo')
      }
      return done(null, userInfo)
  }))

  //stores the whole user from using openID connect + oauth
  passport.serializeUser(function (user, done) {
      return done(null, user)
  })

  passport.deserializeUser(function (user, done) {
      return done(null, user)
  })

  // ######################## OPENID CONNECT STRATEGY #############################

  app.use(express.urlencoded({ extended: true }))
  app.use(passport.initialize())

  function redirectIfLoggedIn(req, res, next) {
    const token = req.cookies.jwt; // Assuming the token is stored in a cookie named 'jwt'
    if (token) {
      try {
        // Verify token. Ensure your jwtSecret is accessible here.
        jwt.verify(token, jwtSecret);
        // If the token is valid, redirect to home page
        return res.redirect('/');
      } catch (err) {
        // If the token verification fails, continue to the login page
        console.log("Invalid token:", err);
      }
    }
    // No valid token found, proceed to the login page
    next();
  }

  app.get('/',
    passport.authenticate(
      'jwtCookie',
      { session: false, failureRedirect: '/login' }
    ),
    (req, res) => {
    
      res.send(`Welcome to your private page, ${req.user.sub}!`)
    }
  )

  app.get('/login',redirectIfLoggedIn,
    (req, res) => {
      res.sendFile('login.html', { root: __dirname })
    }
  )
  app.post('/login', (req, res, next) => {
    // First, try to authenticate using 'local-radius'
    passport.authenticate('local-radius', { session: false }, (err, user, info) => {
      if (err) {
        console.error('Error during local-radius authentication:', err);
        return next(err); // handle unexpected errors
      }
      if (!user) {
        console.log('local-radius failed, info:', info);
        // If 'local-radius' fails, try 'username-password'
        return passport.authenticate('username-password', { session: false }, (err, user, info) => {
          if (err) {
            //console.error('Error during username-password authentication:', err);
            //return next(err); // handle unexpected errors
          res.redirect('/login');
          }
          if (!user) {
            console.log('username-password also failed, info:', info);
            return res.redirect('/login'); // both strategies failed
          }
          // User authenticated with 'username-password'
          return loginUser(req, res, user);
        })(req, res, next);
      }
      // User authenticated with 'local-radius'
      return loginUser(req, res, user);
    })(req, res, next);
  });
  
  function loginUser(req, res, user) {
    req.user = user; // Set the user to req.user
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // Token valid for one week
      role: 'user'
    };
  
    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie('jwt', token, { httpOnly: true, secure: true }); // Ensure 'secure: true' is used in HTTPS environments
    res.redirect('/');
  
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
  }
  

  app.get('/logout', (req, res) => {

    res.clearCookie('jwt');
    res.redirect('/login');
    
  });

  app.get('/oauth2cb', async (req, res) => {

    // 1. Retrieve the authorization code from the query parameters
    const code = req.query.code
    if (code === undefined) {
      const err = new Error('no code provided')
      err.status = 400
      throw err
    }
    //2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
    const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
      client_id: process.env.OAUTH2_CLIENT_ID,
      client_secret: process.env.OAUTH2_CLIENT_SECRET,
      code
    })
    // response.data contains the params of the response, 
    //including access_token, scopes granted by the use and type.
    console.log(tokenResponse.data)


    const params = new URLSearchParams(tokenResponse.data)
    const accessToken = params.get('access_token')
    const scope = params.get('scope')

    // if the scope does not include what we wanted, authorization fails
    if (scope !== 'user:email') {
      const err = new Error('user did not consent to release email')
      err.status = 401
      throw err
    }
    //3. Use the access token to retrieve the user email from the USER_API endpoint
    const userDataResponse = await axios.get(process.env.USER_API, {
      headers: {
        Authorization: `Bearer ${accessToken}`
        }
    })
    console.log(userDataResponse.data);
    console.log(userDataResponse.data.login);

    //4. Create our JWT using the github email as subject, and set the cookie.
    
    const jwtClaims = {
        sub: userDataResponse.data.email,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800,
        role: 'user'
      }

      const token = jwt.sign(jwtClaims, jwtSecret)

      res.cookie('jwt', token, { httpOnly: true, secure: true }) 
      res.redirect('/')

  })

  app.get('/oidc/login', passport.authenticate('oidc', { scope: 'openid email' }))

  //Callback from oidc and creates the jwt token
  app.get('/oidc/cb', passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), (req, res) => {
    
    const jwtClaims = {
            sub: req.user.email,
            iss: 'localhost:3000',
            aud: 'localhost:3000',
            exp: Math.floor(Date.now() / 1000) + 604800,
            role: 'user'
    }

    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token, { httpOnly: true, secure: true }) 
    res.redirect('/')
    
  })

  app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

  app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
  })
}

main().catch(e => { console.log(e) })
