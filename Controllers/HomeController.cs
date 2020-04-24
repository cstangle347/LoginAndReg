using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoginReg.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace LoginReg.Controllers
{
    public class HomeController : Controller
    {
        private MyContext _context { get; set; }
    
        public HomeController(MyContext context)
        {
            _context = context;
        }


        [HttpGet("")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost("register")]
        public IActionResult Register(User newUser)
        {
            if (ModelState.IsValid)
            {
                if (_context.Users.Any( u => u.Email == newUser.Email))
                {
                    ModelState.AddModelError("Email", "is used.");
                }
            }

            if (ModelState.IsValid == false)
            {
                //displays all errors
                return View("Index");
            }

            //hasing pw
            PasswordHasher<User> hasher = new PasswordHasher<User>();
            newUser.Password = hasher.HashPassword(newUser, newUser.Password);

            newUser.CreatedAt = DateTime.Now;
            newUser.UpdatedAt = DateTime.Now;
            _context.Users.Add(newUser);
            _context.SaveChanges();

            HttpContext.Session.SetInt32("UserId", newUser.UserId);
            return RedirectToAction("Success");

        }

        [HttpGet("success")]
        public IActionResult Success()
        {
            if(HttpContext.Session.GetInt32("UserId") == null)
            {
                return RedirectToAction("Logout");
            }
            else
            {
                return View();
            }
        }

        [HttpGet("logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }

        [HttpGet("login")]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost("loggin")]
        public IActionResult Loggin(LoginUser loginUser)
        {
            string myErrorMsg = "Invalid Email or Password";

            if (ModelState.IsValid == false)
            {
                return View("Login");
            }

            User dbUser = _context.Users.FirstOrDefault( u => u.Email == loginUser.LoginEmail );

            if( _context == null)
            {
                ModelState.AddModelError("Login Email", myErrorMsg);
            }
            else
            {
                PasswordHasher<LoginUser> hasher = new PasswordHasher<LoginUser>();

                PasswordVerificationResult result = hasher.VerifyHashedPassword(loginUser, dbUser.Password, loginUser.LoginPassword);
            
                if (result == 0)
                {
                    ModelState.AddModelError("LoginEmail", myErrorMsg);
                }
            }

            if(ModelState.IsValid == false)
            {
                return View("Login");
            }
            
            HttpContext.Session.SetInt32("UserId", dbUser.UserId);
            return RedirectToAction("Success");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
