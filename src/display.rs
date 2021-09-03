use console::Style;

/// Displays a styled message
pub fn print_style(message: &str, style: &str) {
    println!("{}", Style::from_dotted_str(style).apply_to(message));
}

/// Displays a message in the error style
pub fn print_error(message: &str) {
    print_style(message, "red.bold");
}

/// Displays a message in the neutral style
pub fn print_neutral(message: &str) {
    print_style(message, "white.bold");
}

/// Displays a message in the success style
pub fn print_success(message: &str) {
    print_style(message, "green.bold");
}
