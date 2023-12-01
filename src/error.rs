use std::net::IpAddr;

#[derive(Debug)]
pub enum Socks5Error {
    NonSupportedAuth,
    InvalidCommand,
    InvalidVersion(u8),
    InvalidCredential,
    ResolveDnsDisabled,
    Ipv6Disabled,
    Ipv4Disabled,
    BindDstMismatach((IpAddr, IpAddr)),
    Io(std::io::Error),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Error::NonSupportedAuth => write!(f, "Non-supported authentication method"),
            Socks5Error::InvalidVersion(version) => write!(f, "Invalid SOCKS version, version: {}", version),
            Socks5Error::InvalidCredential => write!(f, "Invalid credentials"),
            Socks5Error::InvalidCommand => write!(f, "Invalid command"),
            Socks5Error::Ipv4Disabled => write!(f, "Ipv4 is disabled"),
            Socks5Error::Ipv6Disabled => write!(f, "Ipv6 is disabled"),
            Socks5Error::ResolveDnsDisabled => write!(f, "Dns resolution is disabled"),
            Socks5Error::BindDstMismatach((expected, got)) => write!(f, "Expected bind from {}, instead got {}", expected, got),
            Socks5Error::Io(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for Socks5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Socks5Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Socks5Error {
    fn from(value: std::io::Error) -> Self {
        Socks5Error::Io(value)
    }
}


