use std::{fmt::Display, io::Write};

use anyhow::{anyhow, Result};
use console::{Style, Term};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
#[cfg(test)]
use mockall::{predicate::*, *};
use text_io::read;

enum MessageStyle {
    Error,
    Neutral,
    Success,
}

/// An interface for interacting with the user over the console
#[cfg_attr(test, automock)]
pub trait Console {
    /// Attempts to open the browser to the URL from the CLI
    fn browser(&self, url: &str);

    /// Displays an error message
    fn error(&self, message: &str);

    /// Prompts the user for text input
    fn input(&self, prompt: &str, default: Option<String>, text: Option<String>) -> Result<String>;

    /// Displays neutral message
    fn neutral(&self, message: &str);

    /// Prompts the user for a password
    fn password(&self, prompt: &str) -> Result<String>;

    /// Prompts the user to select an option
    fn select<D: 'static + Display>(
        &self,
        prompt: &str,
        items: &[D],
        default: Option<usize>,
    ) -> Result<Option<usize>>;

    /// Display a success message
    fn success(&self, message: &str);
}

pub struct CLIConsole {
    pub error: String,
    pub neutral: String,
    pub success: String,
    pub theme: ColorfulTheme,
}

impl Console for CLIConsole {
    fn browser(&self, url: &str) {
        self.neutral("Opening browser to OIDC provider...");
        if webbrowser::open(url).is_err() {
            self.error("Failed opening browser. Please manually paste the below URL:");
            self.neutral(url);
        }
    }

    fn error(&self, message: &str) {
        self.print(message, MessageStyle::Error);
    }

    fn input(&self, prompt: &str, default: Option<String>, text: Option<String>) -> Result<String> {
        let mut inp = Input::with_theme(&self.theme);
        if let Some(v) = default {
            inp.default(v);
        }

        inp.with_prompt(prompt)
            .with_initial_text(text.unwrap_or_else(|| String::from("")))
            .interact()
            .map_err(|e| e.into())
    }

    fn neutral(&self, message: &str) {
        self.print(message, MessageStyle::Neutral);
    }

    fn password(&self, prompt: &str) -> Result<String> {
        Password::with_theme(&self.theme)
            .with_prompt(prompt)
            .interact()
            .map_err(|e| e.into())
    }

    fn select<D: 'static + Display>(
        &self,
        prompt: &str,
        items: &[D],
        default: Option<usize>,
    ) -> Result<Option<usize>> {
        Select::with_theme(&self.theme)
            .items(items)
            .default(default.unwrap_or(0))
            .with_prompt(prompt)
            .interact_on_opt(&Term::stderr())
            .map_err(|e| e.into())
    }

    fn success(&self, message: &str) {
        self.print(message, MessageStyle::Success);
    }
}

impl CLIConsole {
    pub fn new() -> Self {
        CLIConsole {
            error: String::from("red.bold"),
            neutral: String::from("white.bold"),
            success: String::from("green.bold"),
            theme: ColorfulTheme::default(),
        }
    }

    fn print(&self, message: &str, style: MessageStyle) {
        match style {
            MessageStyle::Error => {
                println!("{}", self.style(message, &self.error))
            }
            MessageStyle::Neutral => {
                println!("{}", self.style(message, &self.neutral))
            }
            MessageStyle::Success => {
                println!("{}", self.style(message, &self.success))
            }
        }
    }

    fn style<'a>(&self, message: &'a str, style: &str) -> console::StyledObject<&'a str> {
        Style::from_dotted_str(style).apply_to(message)
    }
}

pub struct VanillaConsole;
impl Console for VanillaConsole {
    fn browser(&self, url: &str) {
        self.neutral("Opening browser to OIDC provider...");
        if webbrowser::open(url).is_err() {
            self.error("Failed opening browser. Please manually paste the below URL:");
            self.neutral(url);
        }
    }

    fn error(&self, message: &str) {
        println!("{}", message);
    }

    fn input(&self, prompt: &str, default: Option<String>, _: Option<String>) -> Result<String> {
        print!("{}", prompt);
        match default.as_ref() {
            Some(s) => print!(" [{}]: ", s),
            None => print!(": "),
        };

        std::io::stdout().flush()?;
        let res: String = read!("{}\n");
        Ok(match res.is_empty() {
            true => default.unwrap_or(res),
            false => res,
        })
    }

    fn neutral(&self, message: &str) {
        println!("{}", message);
    }

    fn password(&self, prompt: &str) -> Result<String> {
        print!("{}: ", prompt);

        std::io::stdout().flush()?;
        rpassword::read_password().map_err(|e| e.into())
    }

    fn select<D: 'static + Display>(
        &self,
        prompt: &str,
        items: &[D],
        default: Option<usize>,
    ) -> Result<Option<usize>> {
        println!("{}: ", prompt);
        for (index, item) in items.iter().enumerate() {
            println!("{}. {}", index + 1, item);
        }

        match default {
            Some(i) => print!("Please enter a number [{:#?}]: ", i),
            None => print!("Please enter a number: "),
        };

        std::io::stdout().flush()?;
        let res: String = read!("{}\n");
        let num = match res.is_empty() {
            true => match default {
                Some(i) => i + 1,
                None => return Err(anyhow! {"Invalid selection for login method"}),
            },
            false => res
                .parse()
                .map_err(|_| anyhow! {"Invalid selection for login method"})?,
        };

        if num > items.len() {
            return Err(anyhow! {"Invalid selection for login method"});
        }

        Ok(Some(num - 1))
    }

    fn success(&self, message: &str) {
        println!("{}", message);
    }
}

impl VanillaConsole {
    pub fn new() -> Self {
        VanillaConsole {}
    }
}
