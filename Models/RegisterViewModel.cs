using System.ComponentModel.DataAnnotations;

namespace Task4.Models;

public sealed class RegisterViewModel
{
    [Required(ErrorMessage = "First name is required.")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last name is required.")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Enter a valid e-mail.")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(1, ErrorMessage = "Password must not be empty.")]
    public string Password { get; set; } = string.Empty;
}
