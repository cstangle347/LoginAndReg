using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema; 

namespace LoginReg.Models
{
    [NotMapped]
    public class LoginUser
    {
        [Required(ErrorMessage = "is required.")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string LoginEmail { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "is required.")]
        [MinLength(8, ErrorMessage = "must be at least 8 characters.")]
        [Display(Name = "Password")]
        public string LoginPassword { get; set; }
    }
}