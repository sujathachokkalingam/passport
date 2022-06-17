const express=require("express")
const app=express();
const session=require("express-session")
const hbs=require("express-handlebars")
const mongoose=require("mongoose")
const passport=require("passport")
const localStrategy=require("passport-local").Strategy
 const bcrypt=require("bcrypt")
 const port=process.env.port||9000;
 require("dotenv/config");
 const path=require("path")
const User=require("./model/usermodel.js")

 //mongoodb connection
 mongoose.connect(process.env.DB_URL,
 {useNewUrlParser:true,useUnifiedTopology:true})
.then(()=>{
    console.log("db connected successfully")
})
.catch(err=>{
    console.log(err)
    process.exit(1)
})
//middlewares

app.engine("hbs", hbs.engine({extname:"hbs"}));
app.set("view engine","hbs");


app.use(express.static(__dirname+'/public'));
app.use(session({
    secret:"goodseckret",
    resave:false,
    saveUninitialized:true
}));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

//passport.js
passport.serializeUser((user,done)=>{
    done(null,user.id)
})
passport.deserializeUser((id,done)=>{
    User.findById(id,(err,user)=>{
        done(err,user)
    })
});
passport.use(new localStrategy((username,password,done)=>{
    User.findById({username:username},(err,user)=>{
        if(err)return done(err);
        if(!user) return done(null,false,{message:"incorrect username"})
        bcrypt.compare(password,user.password,(err,res)=>{
            if(err) return done(err);

            if(res==false)
            return done(null,false,{message:"Incorrect password"});
            return done(null,user)
        })
    })
}));
function isLoggedIn(req,res,next){
  if(req.isAuthenticated())
  return next();
  res.redirect("/login")
}
function isLoggedOut(req,res,next){
    if(!req.isAuthenticated())
    return next();
    res.redirect("/")
  }
//calling 
app.get('/',isLoggedIn,(req,res)=>{
    res.render("index",{title:"home"});
})
app.get('/login',isLoggedOut,(req,res)=>{
    const response={
        title:"Login",
        error:req.query.error
    }
    res.render("login",response)
})
app.post('/login',passport.authenticate('local',{
    successRedirect:"/",
    failureRedirect:"/login?error=true"
}));
app.post("/logout",(req,res)=>{
    req.logout();
    req.redirect('/')
})
app.get("/setup",async(req,res)=>{
    const exists=await User.exists({username:"admin"});

    if(exists){
        res.redirect("/login")
        return;
    }
    bcrypt.genSalt(10,(err,salt)=>{
        if(err) return next(err);
        bcrypt.hash("pass",salt,(err,hash)=>{
            if(err) return next();
            const newAdmin=new User({
                username:"admin",
                password:hash
            });
            newAdmin.save();
            res.redirect("/login")
        })
    })
})
app.listen(port,()=>{
    console.log("server running on port${9000}")
})