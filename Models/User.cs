using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LoginReg.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }

        [Required(ErrorMessage = "is required.")]
        [MinLength(2, ErrorMessage = "must be at least 2 characters.")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "is required.")]
        [MinLength(2, ErrorMessage = "must be at least 2 characters.")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "is required.")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "is required.")]
        [MinLength(8, ErrorMessage = "must be 8 characters or longer!")]
        public string Password { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

        //NotMapped Annotation so that the variable is not out database

        [NotMapped]
        [Compare("Password", ErrorMessage = "Password doesn't match")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm PW")]
        public string Confirm { get; set; }

    }
}