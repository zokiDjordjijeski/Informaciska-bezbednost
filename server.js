require('dotenv').config({ path: './.env' });
console.log('JWT_SECRET on startup:', process.env.JWT_SECRET);

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const { trace } = require('console');
const cron = require('node-cron');



const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

app.use(bodyParser.urlencoded({ extended: true}));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret:'VCynemNIw8',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
}));

const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASS,
    {
        host: process.env.DB_HOST,
        dialect: process.env.DB_DIALECT,
    }
);

const User = sequelize.define('profil', {
    username: { type: DataTypes.STRING, allowNull: false, },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    salt: { type: DataTypes.STRING, allowNull: false },
    IsVerified: { type:DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    verificationRegisterCode: {type: DataTypes.STRING, allowNull: true },
    codeRegisterExpires: { type: DataTypes.DATE, allowNull: true },
    verificationLoginCode: {type: DataTypes.STRING, allowNull: true },
    codeLoginExpires: { type: DataTypes.DATE, allowNull: true },

    role: { type: DataTypes.STRING, allowNull: false, defaultValue: 'user'}

});

sequelize.sync()
    .then(()=>console.log('Database synchtonized.'))
    .catch(err=> console.log('Error syncing database:', err));



sendVerificationEmail = async(user, token) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        auth:{
            user: process.env.DB_EMAIL,
            pass: process.env.DB_PASSWORD,
        }
    });
    const verificationLink = `http://localhost:${process.env.PORT}/verify/${token}`;
    await transporter.sendMail({
        from: `"My Cool App" <${process.env.DB_EMAIL}>`,
        to: user.email,
        subject: 'Verify Your Email',
        html: `<p>Hello ${user.username},</p>
               <p>Please verify your email by clicking the link below:</p>
               <a href="${verificationLink}">${verificationLink}</a>`,
    });
};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Register.html'));
});

app.post('/register', async (req, res) => {
    const{ username, email, password } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if(!emailRegex.test(email)){
        return res.redirect(`/Register.html?error=invalid%20email%20format`);
    }
    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.redirect(`/Register.html?error=User%20already%20exists2`);
        }
        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = await bcrypt.hash(password + salt, 12);

        const newUser = await User.create({
            username,
            email,
            password: hashedPassword,
            salt: salt,
            role: email === process.env.DB_EMAIL? 'admin' : 'user',

            //     verificationRegisterCode: {type: DataTypes.STRING, allowNull: true },
            //     codeRegisterExpires: { type: DataTypes.DATE, allowNull: true },
            //     verificationLoginCode: {type: DataTypes.STRING, allowNull: true },
            //     codeLoginExpires: { type: DataTypes.DATE, allowNull: true },
        });


        const verificationToken = jwt.sign({ email: newUser.email }, process.env.JWT_SECRET, {expiresIn: '2h' });
        const expirationTime = new Date(Date.now() + 2 * 60 *60* 1000);

        newUser.verificationRegisterCode = verificationToken;  //Added this
        newUser.codeRegisterExpires=expirationTime;
        await newUser.save();   //And this

        await sendVerificationEmail(newUser, verificationToken);
        // res.redirect(`${frontendUrl}/Lab.2/public/Waiting%20for%20verification.html`);
        res.send('Registration is complete! Waiting for user to verify his account.');
    }
    catch (error) {
        console.error('Error during registration: ', error);
        res.redirect(`/Register.html?error=User%20already%20exists.`);
        // ${frontendUrl}/Lab.2/auth-backend/public/Register.html?error=User%20already%20exists.
    }
});

app.get('/verify/:token', async (req, res) => {
    const { token } = req.params;

    try{

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findOne({ where: {email: decoded.email } }); //added verificationToken
        if(!user){
            return res.status(400).send('Invalid token or user does not exist.');
        }

        user.IsVerified = true;

        await user.save();

        res.redirect('/login');
    } catch(error){
        console.error('Verification error: ', error.message);
        res.status(400).send('Invalid or expired token.');
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'Login.html'));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try{
        const user = await User.findOne({ where: { email }});
        console.log("USERot : "+user+"\nEMAILot: "+email);
        if(!user){
            return res.redirect(`/Login.html?error=Invalid%20email%20or%20password.1`);
        }
        if(!user.IsVerified){
            return res.redirect(`/Login.html?error=The%20user%20is%20not%20verified.%20Please%20verify%20your%20account.`);
        }
        const isPasswordValid = await bcrypt.compare(password + user.salt, user.password);
        if(!isPasswordValid){
            return res.redirect(`/Login.html?error=Invalid%20email%20or%20password.`);
        }
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expirationTime = new Date(Date.now() + 3*5 * 60 * 1000);
        user.verificationLoginCode = verificationCode;
        user.codeLoginExpires = expirationTime;
        await user.save();
        const transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
                user: 'april.prohaska97@ethereal.email',
                pass: 'ubYtGrPBQSh2vdjkdS',
            }
        });
        await transporter.sendMail({
            from: `"My Cool App" <${process.env.DB_EMAIL}>`,
            to: user.email,
            subject: 'Your 2FA Code',
            html:  `<p>Hello ${user.username},</p>
                    <p>Your 2FA verification code is: <strong>${verificationCode}</strong></p>
                    <p>This code will expire in 5 minutes.</p> `,
        });
        req.session.email = email;
        req.session.verificationLoginCode = verificationCode;
        res.redirect(`/2FA.html`);
    } catch (error) {
        console.error('Error during login: ', error);
        res.redirect(`/Login.html?error=An%20unexpected%20error%20has%20occured.`);
    }
});

app.post('/verify-2fa', async (req, res) => {

    email = req.session.email;
    verificationCode = req.session.verificationLoginCode;

    if(!email){
        return res.redirect('/Login.html?error=Session%20expired');
    }
    try{
        const user = await User.findOne({ where: { email } });
        if(!user){
            return res.redirect(`/Login.html?error=User%20does%20not%20exist`);
        }
        console.log('Codes: ', user.verificationLoginCode, verificationCode);
        if(user.verificationLoginCode !== verificationCode || new Date > new Date(user.codeExpires)){
            return res.redirect(`/Login.html?error=Verification%20code%20is%20wrong%20or%20it%20has%20expired.`);
        }

        user.verificationCode = null;
        user.codeExpires = null;
        await user.save();



        res.redirect(`/Home.html`);
    } catch (error) {
        console.error('Error verifyign 2FA code: ', error);
        res.status(500).send('An error occured. Please try again.');
    }
});

function isAdmin(req, res, next) {
    const email = req.session.email;
    if(!email){
        return res.redirect('/login');
    }
    User.findOne({ where: { email }})
        .then(user =>{
            if(user && user.role === 'admin'){
                next();
            }
            else{
                res.status(403).send('Forbidden: You do not have permission to access this resource.')
            }
        })
        .catch (err => {
            console.error('Error in isAdmin middleware:', err);
            res.status(500).send('Internal Server Error');
        });

}


app.get('/users', isAdmin, async(req, res) =>{
    try{
        const users = await User.findAll();
        res.render('view', { users: users});
    } catch (error){
        console.error('Error fetching users:', error);
    }
});


app.use(bodyParser.json());

app.post('/update-roles', async (req, res) => {
    const { email, role } = req.body;

    if (!email || !role) {
        return res.status(400).send('Invalid data provided.');
    }

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(404).send('User not found.');
        }

        // Ажурирање на улогата
        user.role = role;
        await user.save();

        res.status(200).send('Role updated successfully.');
    } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).send('Internal Server Error.');
    }
});

// app.get('/change-role', async (req, res) =>{
//     const { role } = req.body;
//     const email = req.session.email;

//     if(!email){
//         return res.redirect(`/Login.html?error=Not%20logged%20in`);
//     }

//     try{
//         const user = await User.findOne({ where: { email }});
//         if(!user){
//             return res.status(404).json({ error: 'User not found' });
//         }

//         const validRoles = ['admin', 'user'];
//         if(!validRoles.includes(user.role)){
//             return res.status(400).json({ error: 'Invalid role' });
//         }
//         const expirationDate = new Date();

//         expirationDate.setMinutes(expirationDate.getMinutes() + 5);

//         await user.update({
//             role: 'admin',
//             tempRoleExpires: expirationDate,
//         });

//         return res.redirect(`Home.html?message=Role%20updated%20to%20admin%20successfully.`);
//     } catch(error){
//         console.error('Error changing role: ', error);
//         return res.status(500).json({ error: 'internal server error, its here'});
//     }
// });

//     app.get('/send-home', async(req, res) =>{

//        try{
//             const user = await User.findOne({ where: {email: req.session.email} } );

//             user.update({
//                 role: 'user',
//                 tempRoleExpires: null,
//             });

//             res.redirect(`/Home.html`);
//        } catch (error){
//         console.error('System error');
//        }
//     })
// const  authorize = (roles) => {
//     return async(req, res, next) =>{
//         try{

//         if(!req.session.email){
//             return res.redirect(`/Login.html`);
//         }

//        const user = await User.findOne({ where: { email: req.session.email } })

//             if (!user){
//                 return res.status(403).send('Access denied.');
//             }

//             const validRoles = ['admin'];
//             if(!validRoles.includes(user.role)){
//                 return res.status(403).send('Access denied.Invalid role');
//             }
//             // user.update({
//             //     role: validRoles,
//             //     tempRoleExpires:
//             // })
//             next();
//         } catch(error) {
//             console.error('Authorization error: ', error);
//             res.status(500).send('Internal server error. its there');
//         }
//     };
// };

// app.get('/admin', authorize(['admin']), (req, res) =>{
//     res.redirect(`APage.html`);
// });


// app.get('/home', authorize(['admin']), async (req, res) => {
//     try {
//         const user = await User.findOne({ where: { email: req.session.email } });

//         if (!user) {
//             return res.redirect('/Login.html?error=Session%20expired%20or%20user%20not%20found');
//         }


//         const roleMessage = `Welcome, ${user.username}! Your role is: ${user.role}`;
//     } catch (error) {
//         console.error('Error rendering Home page:', error);
//         res.status(500).send('An unexpected error occurred.');
//     }
// });

// cron.schedule('*/5 * * * *', async () =>{
//     try{
//         const expiredUsers = await User.findAll({
//             where:{
//                 tempRoleExpires:{
//                     [Sequelize.Op.lt]: new Date(),
//                 }
//             }
//         });

//         for( const user of expiredUsers){
//             await user.update({
//                 role: 'user',
//                 tempRoleExpires: null,
//             });
//         }
//         console.log('Expired roles have been cleaned up.');
//     } catch(error){
//         console.error('Error cleaning up expired roles:', error);
//     }
// })

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
