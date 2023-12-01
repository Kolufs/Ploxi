use std::{
    net::SocketAddr,
    time::Duration, 
};

use auth::{UserPassAuth, NoAuthentication, IpAuth};
use clap::{Parser, Subcommand};
use server::Config;

#[macro_use]
extern crate log;

extern crate pretty_env_logger;

mod auth;
mod server;
mod utils;
mod error;

#[derive(Debug, Subcommand)]
enum Auth {
    UserPass(UserPassAuth),
    NoAuth(NoAuthentication),
    Ip(IpAuth),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap()]
    address: SocketAddr,

    #[clap(flatten)]
    atyp: Atyp,

    #[clap(flatten)]
    cmd: Cmd,
    
    #[clap(subcommand)]
    auth: Auth, 

    /// Sets the read timeout for the sockets
    #[clap(short, long, value_parser = parse_duration)]
    timeout: Duration,

}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = true)]
struct Atyp {
    /// Allow ipv6 atyp
    #[clap(long)]
    ipv6: bool,

    /// Allow ipv4 atyp
    #[clap(long)]
    ipv4: bool,

    /// Allow domain atyp
    #[clap(long)]
    domain: bool,
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = true)]
struct Cmd {
     /// Allow bind command
    #[clap(long)]
    bind: bool,

    /// Allow connect command
    #[clap(long)]
    connect: bool,

    /// Allow for udp_associate command
    #[clap(long)]
    udp:bool,
}

fn main() {
    pretty_env_logger::init();
    let args = Args::parse(); 
    match args.auth {
        Auth::Ip(v) => {
            let config = Config {
                socket_address: args.address, 
                connect: args.cmd.connect,
                bind: args.cmd.bind, 
                udp_associate: args.cmd.udp, 
                ipv4: args.atyp.ipv4, 
                ipv6: args.atyp.ipv6, 
                resolve_dns: args.atyp.domain,
                read_timeout: args.timeout,
                auth: v
            };
            let ser = server::SocksServer::new(config).unwrap();
            ser.serve();
        }
        Auth::NoAuth(v) => {
            let config = Config {
                socket_address: args.address, 
                connect: args.cmd.connect,
                bind: args.cmd.bind, 
                udp_associate: args.cmd.udp, 
                ipv4: args.atyp.ipv4, 
                ipv6: args.atyp.ipv6, 
                resolve_dns: args.atyp.domain,
                read_timeout: args.timeout,
                auth: v
            };
            let ser = server::SocksServer::new(config).unwrap();
            ser.serve();
        }
        Auth::UserPass(v) => {
            let config = Config {
                socket_address: args.address, 
                connect: args.cmd.connect,
                bind: args.cmd.bind, 
                udp_associate: args.cmd.udp, 
                ipv4: args.atyp.ipv4, 
                ipv6: args.atyp.ipv6, 
                resolve_dns: args.atyp.domain,
                read_timeout: args.timeout,
                auth: v
            };
            let ser = server::SocksServer::new(config).unwrap();
            ser.serve();
        }
    } 
}
