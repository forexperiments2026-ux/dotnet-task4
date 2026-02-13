namespace Task4.Configuration;

public sealed class EmailConfirmationOptions
{
    public int TokenLifetimeHours { get; set; } = 24;
}
