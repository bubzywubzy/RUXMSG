//! REPL command model and parser.

// =====================================================================
// COMMAND MODEL
// =====================================================================

pub(crate) enum Command {
    Profile(ProfileCommand),

    Start { addr: String },

    Stop,

    Connect { addr: String },

    Peers,

    Use { label: String },

    Message { label: String, text: String },

    Close { label: String },

    Rekey { label: String },

    Fingerprint { label: Option<String> },

    Session { label: String },

    Chat { label: Option<String> },

    Tailscale(TailscaleCommand),

    Help,

    Quit,
}

pub(crate) enum ProfileCommand {
    Init(String),
    Use(String),
    List,
}

pub(crate) enum TailscaleCommand {
    Status,
    Up,
    Ip,
}

pub(crate) struct CommandParser;

impl CommandParser {
    pub(crate) fn parse(line: &str) -> Result<Command, String> {
        let line = line.trim();

        if line.is_empty() {
            return Err("empty command".into());
        }

        let mut words = line.split_whitespace();

        let command = words.next().unwrap_or_default();

        match command {
            "profile" => Self::parse_profile(words),

            "start" => {
                let args: Vec<_> = words.collect();

                if args.is_empty() {
                    return Ok(Command::Start {
                        addr: "127.0.0.1:4443".to_string(),
                    });
                }

                if args.len() == 2 && args[0] == "--addr" {
                    return Ok(Command::Start {
                        addr: args[1].to_string(),
                    });
                }

                Err("usage: start [--addr <addr>]".into())
            }

            "stop" => Self::no_args(words, Command::Stop, "stop"),

            "connect" => {
                let addr = words
                    .next()
                    .ok_or_else(|| "usage: connect <addr>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: connect <addr>".into());
                }

                Ok(Command::Connect {
                    addr: addr.to_string(),
                })
            }

            "peers" => Self::no_args(words, Command::Peers, "peers"),

            "use" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: use <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: use <label>".into());
                }

                Ok(Command::Use {
                    label: label.to_string(),
                })
            }

            "msg" => {
                const USAGE: &str = "usage: msg <label> <text>";

                // Skip the command word, then the label, tolerating runs of
                // whitespace; the remainder is the message verbatim.
                let rest = line.trim_start()["msg".len()..].trim_start();
                let (label, text) = rest.split_once(char::is_whitespace).ok_or(USAGE)?;
                let text = text.trim();
                if label.is_empty() || text.is_empty() {
                    return Err(USAGE.to_string());
                }

                Ok(Command::Message {
                    label: label.to_string(),
                    text: text.to_string(),
                })
            }

            "close" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: close <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: close <label>".into());
                }

                Ok(Command::Close {
                    label: label.to_string(),
                })
            }

            "rekey" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: rekey <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: rekey <label>".into());
                }

                Ok(Command::Rekey {
                    label: label.to_string(),
                })
            }

            "fingerprint" => {
                let label = words.next().map(str::to_string);

                if words.next().is_some() {
                    return Err("usage: fingerprint [label]".into());
                }

                Ok(Command::Fingerprint { label })
            }

            "session" => {
                let label = words
                    .next()
                    .ok_or_else(|| "usage: session <label>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: session <label>".into());
                }

                Ok(Command::Session {
                    label: label.to_string(),
                })
            }

            "chat" => {
                let label = words.next().map(str::to_string);

                if words.next().is_some() {
                    return Err("usage: chat [label]".into());
                }

                Ok(Command::Chat { label })
            }

            "tailscale" => Self::parse_tailscale(words),

            "help" => Self::no_args(words, Command::Help, "help"),

            "quit" | "exit" => Self::no_args(words, Command::Quit, "quit"),

            _ => Err(format!("unknown command: {command}; type `help`")),
        }
    }

    pub(crate) fn parse_profile<'a>(
        mut words: impl Iterator<Item = &'a str>,
    ) -> Result<Command, String> {
        let subcommand = words
            .next()
            .ok_or_else(|| "usage: profile <init|use|list> ...".to_string())?;

        match subcommand {
            "init" => {
                let name = words
                    .next()
                    .ok_or_else(|| "usage: profile init <name>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: profile init <name>".into());
                }

                Ok(Command::Profile(ProfileCommand::Init(name.to_string())))
            }

            "use" => {
                let name = words
                    .next()
                    .ok_or_else(|| "usage: profile use <name>".to_string())?;

                if words.next().is_some() {
                    return Err("usage: profile use <name>".into());
                }

                Ok(Command::Profile(ProfileCommand::Use(name.to_string())))
            }

            "list" => Self::no_args(
                words,
                Command::Profile(ProfileCommand::List),
                "profile list",
            ),

            _ => Err("usage: profile <init|use|list> ...".into()),
        }
    }

    pub(crate) fn parse_tailscale<'a>(
        mut words: impl Iterator<Item = &'a str>,
    ) -> Result<Command, String> {
        let subcommand = words.next().unwrap_or("status");

        if words.next().is_some() {
            return Err("usage: tailscale <status|up|ip>".into());
        }

        let command = match subcommand {
            "status" => TailscaleCommand::Status,
            "up" => TailscaleCommand::Up,
            "ip" => TailscaleCommand::Ip,
            _ => return Err("usage: tailscale <status|up|ip>".into()),
        };

        Ok(Command::Tailscale(command))
    }

    pub(crate) fn no_args<'a>(
        mut words: impl Iterator<Item = &'a str>,
        command: Command,
        usage: &str,
    ) -> Result<Command, String> {
        if words.next().is_some() {
            return Err(format!("usage: {usage}"));
        }

        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_input_is_not_interpreted_as_a_message() {
        assert!(matches!(
            CommandParser::parse("conect peer"),
            Err(error) if error == "unknown command: conect; type `help`"
        ));
    }

    #[test]
    fn explicit_message_command_keeps_the_message_text() {
        let Command::Message { label, text } =
            CommandParser::parse("msg peer  words stay intact ").unwrap()
        else {
            panic!("expected a message command");
        };
        assert_eq!(label, "peer");
        assert_eq!(text, "words stay intact");
    }
}
