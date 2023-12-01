use std::{
    error::Error,
    io::{Read, Write},
    net::{IpAddr, TcpStream},
};

use clap::Parser;

use crate::error::Socks5Error;

use crate::{read_byte, read_bytes};

pub trait Authenticator: Send + Sync {
    const METHOD: u8;
    type Error: Send + Sync + Error;

    fn authenticate(&self, comm: &mut TcpStream) -> Result<(), Self::Error>;
}

#[derive(Debug, Parser)]
pub struct NoAuthentication;

impl Default for NoAuthentication {
    fn default() -> Self {
        NoAuthentication
    }
}

impl Authenticator for NoAuthentication {
    const METHOD: u8 = 0x00;
    type Error = Socks5Error;

    fn authenticate(&self, _comm: &mut TcpStream) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UserPassAuth {
    username: String,
    password: String,
}

impl Authenticator for UserPassAuth {
    const METHOD: u8 = 0x2;
    type Error = Socks5Error;
    fn authenticate(&self, comm: &mut TcpStream) -> Result<(), Self::Error> {
        debug!("Starting UserPassAuth");
        let [ver, ulen] = read_bytes!(comm, 2);
        if ver != 0x01 {
            debug!("Invalid UserPassAuth ver, ver: {}", ver);
            return Err(Socks5Error::InvalidVersion(ver));
        }

        let mut name: Vec<u8> = vec![0; ulen as usize];
        comm.read_exact(&mut name)?;
        let name = String::from_utf8_lossy(&name);

        let mut plen = 0;
        read_byte!(comm, plen)?;
        let mut password = vec![0; plen as usize];
        comm.read_exact(&mut password)?;
        let password = String::from_utf8_lossy(&password);

        debug!(
            "UserPassAuth:
        username: {}
        password: {}",
            name, password
        );

        let answer: [u8; 2];
        match name.to_string() == self.username && password.to_string() == self.password {
            true => {
                answer = [0x01, 0x00];
                comm.write_all(&answer)?;
                debug!("UserPassAuth valid creds");
                Ok(())
            }
            false => {
                answer = [0x01, 0x01];
                comm.write_all(&answer)?;
                debug!("UserPassAuth invalid creds");
                Err(Socks5Error::InvalidCredential)
            }
        }
    }
}

#[derive(Debug, Parser)]
pub struct IpAuth {
    ip: IpAddr,
}

impl Authenticator for IpAuth {
    const METHOD: u8 = 0x00;
    type Error = Socks5Error;

    fn authenticate(&self, comm: &mut TcpStream) -> Result<(), Self::Error> {
        match comm.peer_addr().unwrap().ip() == self.ip {
            true => Ok(()),
            false => Err(Socks5Error::InvalidCredential)
        }
    }
}


