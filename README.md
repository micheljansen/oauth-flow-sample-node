# Sample OAuth Flow for Node
This is based on the Smartsheet sample flow (see [this blog post](https://developers.smartsheet.com/blog/creating-smartsheet-oauth-flow-in-node). It allows users to go through the Smartsheet authentication flow to get an authentication token, which is then stored in a session. It also shows how to then use it to access a sheet. 

This sample demonstrates a lightweight implementation of the Smartsheet OAuth flow using an express server. To configure this sample to work for with your own app there are three important changes to pay attention to:
- Register your application with Smartsheet and fill out all the fields. 
- Changing the `config.json` file to include the client id and client secret of your app.
- Double check the **Redirect URL** in app settings. Smartsheet will **only** send the authorization code to that URL. This example uses `localhost:3000/callback` but your app will have its' own **Redirect URL**. 

#### Step 1: Register a Developer Account
 - [Register a developer account](https://developers.smartsheet.com/register) with Smartsheet. This gives your Smartsheet account access to 'Developer Tools'. Registering for a developer account will create a new Smartsheet account. Be sure to use an email address that isn't already associated with an existing Smartsheet account.

#### Step 2: Register Your App with Smartsheet 

 1. On the top right corner of Smartsheet, select **Account** then **Developer Tools**. 
 2. Click **Create New App** and fill out the following information:
	- Name: the name users see to identify your app
	- Description: a brief description meant for the user
	- URL: the URL to launch your app, or landing page if not a web app
	- Contact: support information for the user
	- Redirect URL*: sometimes called the callback URL. The URL within your app that will receive the OAuth 2.0 credentials.
 3. Click **Save** to create the app. Smartsheet will assign a ***client Id*** and a ***client secret***. You'll need both to create your OAuth flow.

*The redirect URL will contain sensitive information and **must** be an address that the developer has control over. In this sample we are using localhost:300/callback, but your application will have its' own redirect URL. 
#### Step 3: Create the OAuth Flow
  
 1. Open the `config.json` file and replace the placeholder values with the ***client Id*** and ***client secret*** from your app. You also need to specify the desired [**access scopes**](https://smartsheet-platform.github.io/api-docs/#access-scopes).
For this example, we'll just provide access to `READ_SHEETS`.
```
{
  "APP_CLIENT_ID": "your_client_id",
  "APP_SECRET": "your_client_secret",
  "ACCESS_SCOPE":"READ_SHEETS"
}
```
 1. Run `npm install` to download the modules
 2. Start the app with `node auth.js`
 3. Go to *localhost:3000* in your browser. Click through the OAuth flow to make sure everything works.
	 - Click **Login to Smartsheet**. You should be redirected to this window:
	 ![enter image description here](https://lh3.googleusercontent.com/-A5IFP3Esa94/Wjmw5x5_MZI/AAAAAAAAAJs/vTXXwHhX3lIC3Ztu1zqKpTVmOyYWylzlgCLcBGAs/s0/Screen+Shot+2017-12-19+at+4.34.35+PM.png "SmartsheetAuthPermission")
	 - Click **Allow**. You should be sent to your redirect URL with your shiny new access token displayed on the page.
	 ![enter image description here](https://lh3.googleusercontent.com/Fi8d-Bd62BHhsOiBKdIvbAY2lzSFgDU7fIPOvv5FarUb_gzTo2lK21-y5HhSKYNxe3NI5e-11y76=s0 "ReturnedToken")

Congratulations! You now have a working OAuth flow that successfully (read: hopefully) requests and retrieves an access token from Smartsheet. This access token can be used in your app to interact directly with the Smartsheet API. 

#### Refreshing the Access Token
You'll need to periodically refresh the Access Token as it expires 7 days after being issued. However, rather than going through the full OAuth Flow again, a better option is to use the Refresh Token. Using the refresh_token from your the last successful authorization, you can make a call to a refresh token endpoint to issue a new authorization token.

**Important**: This sample app runs on localhost, but implementing OAuth on a production application will have some major differences. The key things to pay attention to:
- The *Redirect URL* must be set to a secure URL on the production server that the developer has control over so the authorization code is safe and can be easily captured.
- Make sure the App Description is polished on Smartsheet. Any customers following the OAuth Flow will see the app description in the authorization window.

Tip: you can use localtunnel to temporarily create an internet-facing endpoint for Smartsheet to call back to. This allows you to, for example, set the app redirect URL of the Smartsheet "App" configuration to https://froq-smartsheet-auth-test.loca.lt/callback 

and then create a tunnel for that URL like this:
> $ lt -p 3000 -s froq-smartsheet-auth-test
> 
> your url is: https://froq-smartsheet-auth-test.loca.lt
