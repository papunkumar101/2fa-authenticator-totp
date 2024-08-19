import express from 'express';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode'; 
import { JsonDB, Config } from 'node-json-db';

const app = express(); 
app.use(express.urlencoded({extended : true}));
const db = new JsonDB(new Config("db/mydb", true, false, '/'));
// await db.push("/test1","super test");

app.get('/', function(req, res){
   return res.send('<a href="/login">Login</a><br/><a href="/register">Register</a>');
});

app.get('/login', function(req, res){ 
    return res.send('<form action="/login" method="POST"><input name="userId" placeholder="User Name" required><br/><input name="password" placeholder="Password" required><br/><button type="submit" value="submit">Login</button></from>'); 
});

app.post('/login', async function(req, res){
    const {userId, password, totp} = req.body;
    if(!userId) return res.send('Please enter correct creds');
    const resp = await db.getData('/'+userId); 
    if(!resp || resp.userId !== userId || resp.password !== password) return res.send('Please enter correct creds');
    // if not empty TOTP - verify here
     if(totp && totp.toString().length == 6){
        let verify = await verifyUserToken(totp, userId);
        console.log('verify',verify);
        if(verify) return res.redirect(`/profile?user=${userId}`);
        else return res.send('TOTP is expaired or wrong - Please try again');
    }
    const is2FAEnable = resp.is2FAEnable;
    if(is2FAEnable){
        return res.send(`<form action="/login" method="POST"><input name="userId" placeholder="User Name" value="${userId}" readonly><br/><input name="password" placeholder="Password" value="${password}" readonly><br/><input name="totp" placeholder="Enter Your TOTP" required><br/><button type="submit" value="submit">Login</button></from>`);
    }
    
    return res.redirect(`/profile?user=${userId}`);
});

app.get('/profile', async function(req, res){
    const {user} = req.query;
    const resp = await db.getData('/'+user);
    if(resp.is2FAEnable){
        return res.send(`Hello ${user}, <br/><a href="/">Logout</a><br/><br/><h3>Disable 2FA : </h3> <br/><a href="/disable-2fa?user=${user}"> Click the link to disable 2FA</a>`);
    }

    const secret = speakeasy.generateSecret({length : 20});
    qrcode.toDataURL(secret.otpauth_url, function(err, data_url){
       if(err) return res.send('error in generating qrcode');    
       return res.send(`Hello ${user}, <br/><a href="/">Logout</a><br/><br/><h3>Enable 2FA : </h3><ul><li>Scan the QR code with your authenticator app</li><li> Enter the TOTP</li><li>Enable the 2FA with verify - click on verify button </li></ul><br><img src="${data_url}"><br/><form action="/enable-2fa" method="POST"><input type="number" placeholder="Enter TOTP" name="totp"><input type="hidden" name="user" value="${user}"><input type="hidden" name="secret" value="${secret.base32}"><button type="submit" value="submit">Verify</button></from>`);
    })
});


app.post('/enable-2fa', async function(req, res){
    const {user, totp, secret} = req.body;
    
    await db.push(`/${user}/is2FAEnable`, true);
    await db.push(`/${user}/secret`, secret);
    let verify = await verifyUserToken(totp, user);
    console.log('verify',verify);
    if(verify)  return res.redirect(`/profile?user=${user}`); 
    else {
        await db.push(`/${user}/is2FAEnable`, false);
        await db.push(`/${user}/secret`, '');
        return res.send('Verify failed - try again');
    }
});


app.get('/disable-2fa', async function(req, res){
    const {user} = req.query;
    await db.push(`/${user}/is2FAEnable`, false);
    await db.push(`/${user}/secret`, '');
    return res.redirect(`/profile?user=${user}`);
});
 
async function verifyUserToken(token, userId) {
  const resp = await db.getData('/'+userId);
  if(!resp.secret) return false; 
  return speakeasy.totp.verify({    
    secret : resp.secret,
    encoding : 'base32',
    token : token
  });
}

app.get('/register', function(req, res){
    return res.send('<form action="/register" method="POST"><input name="userId" placeholder="User Name" required><br/><input name="password" placeholder="Password" required><br/><input name="cpassword" placeholder="Confirm password" required><br/><button type="submit" value="submit">Register</button></from>');
});

app.post('/register', async function(req, res){ 
    const {userId, password, cpassword} = req.body;

    try {
        await db.push("/"+userId, {userId : userId, password : password, is2FAEnable : false, secret : ''});
        return res.redirect('/');
    } catch (error) { 
        console.log(error);
        return res.send('something went wrong, please try again');
    }
});


app.listen(3000, function(){
    console.log('Server listing on port 3000');
});