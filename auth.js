const express = require('express'),
    config = require('./config.json'),
    qs = require('querystring'),
    smarclient = require('smartsheet'),
    session = require('express-session'),
    app = express(),
    fs = require('fs');

const FileStore = require('session-file-store')(session)

app.use(session({
  secret: config.SESSION_SECRET,
  store: new FileStore({}),
  resave: false,
  saveUninitialized: false
}))

var cached_token = null;

// instantiating the Smartsheet client
const smartsheet_unauthenticated = smarclient.createClient({
    // a blank token provides access to Smartsheet token endpoints
    accessToken: ''
});

var smartsheet = null;

// sheet ID for demo purposes. Make sure you use a sheet ID that your Smartsheet user has access to
const SHEET_ID = 94335806689156;

// starting an express server
app.listen(3000, () => {
    console.log('Listening on port 3000...');
});

app.get('/', (req, res) => {
  doAuthenticated(req, res, function(smartsheet) {
    var sheet = smartsheet.sheets.getSheet({ id: SHEET_ID }).then(function(result) {
      //res.send("<pre>"+JSON.stringify(result, null, 2)+"</pre>")
      res.render("index.ejs", {data: result})
    }).error(function(e) {
      res.status(500).send("error:", e);
    })
  })
});

// setting up home route containing basic page content
app.get('/login', (req, res) => {
    res.send('<h1>Sample oAuth flow for Smartsheet</h1><a href="/auth">Login to Smartsheet</a></br><a href="/refresh">Refresh Token</a>')
});

// route redirecting to authorization page
app.get('/auth', (req, res) => {
    console.log('Your authorization url: ', authorizationUri);
    res.redirect(authorizationUri);
});

// helper function to assemble authorization url
function authorizeURL(params) {
    const authURL = 'https://app.smartsheet.com/b/authorize';
    return `${authURL}?${qs.stringify(params)}`;
}
const authorizationUri = authorizeURL({
    response_type: 'code',
    client_id: config.APP_CLIENT_ID,
    scope: config.ACCESS_SCOPE
});

// callback service parses the authorization code, requests access token, and saves it 
app.get('/callback', (req, res) => {
    console.log(req.query);
    const authCode = req.query.code;
    const generated_hash = require('crypto')
        .createHash('sha256')
        .update(config.APP_SECRET + "|" + authCode)
        .digest('hex');
    const options = {
        queryParameters: {
            client_id: config.APP_CLIENT_ID,
            code: authCode,
            hash: generated_hash
        }
    };
    smartsheet_unauthenticated.tokens.getAccessToken(options)
        .then((token) => {
          req.session.token = processToken(token);
          console.log("success!", token);
          res.redirect("/login_success");
          console.log("redirected")
          return;
        }).catch((e) => {
          console.log("getaccess token catch");
          console.log(e)
          //console.log("failure", token);
          return res.send("authorization failed");
        });
});


app.get('/login_success', (req, res) => {
  return res.send("Login success<br><a href='/'>Continue...</a>");
})


app.get('/refresh', (req, res) => {
  if(!req.session.token) {
    // redirect to normal oauth flow if no existing token
    console.log("no token to refresh, login instead")
    res.redirect(authorizationUri);
  }

  const old_token = req.session.token

  // if current date is past expiration date...
  if (Date.now() > old_token.expires_in) {
    const generated_hash = require('crypto')
      .createHash('sha256')
      .update(config.APP_SECRET + "|" + old_token.refresh_token)
      .digest('hex');
    const options = {
      queryParameters: {
        client_id: config.APP_CLIENT_ID,
        refresh_token: old_token.refresh_token,
        hash: generated_hash
      }
    };
    smartsheet_unauthenticated.tokens.refreshAccessToken(options)
      .then((token) => {
        // save token to session
        req.session.token = processToken(token);
        console.log("token refreshed. Redirecting");
        return res.redirect("/login_success");
      })
      .catch((e) => {
        console.log("could not refresh: ",e)
      })
  }
  else {
    // token still valid. If attempting to force token refresh, change expires_in in priv_token.json
    console.log('token still valid')
    return res
      .send('<h1>No refresh. Access token still valid</h1>');
  }
})

app.get('*', (req, res) => {
  console.log("unrouted request", req);
})


function processToken(token) {
    token.expires_at = (Date.now() + (token.expires_in * 1000)) 
    return token;
}

function doAuthenticated(req, res, callback) {
  if(smartsheet) {
    return callback(smartsheet);
  }


  if(!req.session.token) {
    console.log("No token, redirecting to login");
    return res.redirect("/auth");
  }

  const token = req.session.token;
  console.log("have token:", token);

  if (Date.now() > token.EXPIRES_IN) {
    console.log("Token expired, redirecting to refresh");
    return res.redirect("/refresh");
  }

  // token ok, set up client
  smartsheet = smarclient.createClient({accessToken:token.access_token});
  return callback(smartsheet)
}
