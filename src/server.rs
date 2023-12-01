use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::ops::Deref;
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use std::{thread, vec};

use crate::auth::Authenticator;
use crate::{read_byte, read_bytes};
use crate::error::Socks5Error;

pub type SocksResult<T> = std::result::Result<T, Socks5Error>;

#[derive(Debug)]
pub struct Config<A: Authenticator> {
    pub socket_address: SocketAddr,
    pub read_timeout: Duration,
    pub auth: A,
    pub resolve_dns: bool,
    pub ipv6: bool,
    pub ipv4: bool,
    pub connect: bool,
    pub bind: bool,
    pub udp_associate: bool, 
}

impl<A: Authenticator + Default> Default for Config<A> {
    fn default() -> Self {
        Self {
            socket_address: SocketAddr::from_str("127.0.0.1:8080").unwrap(),
            read_timeout: Duration::new(2, 0),
            auth: A::default(),
            resolve_dns: true,
            ipv6: true,
            ipv4: true,
            connect: true,
            bind: true,
            udp_associate: true,
        }
    }
}

#[derive(Debug)]
pub struct SocksServer<A: Authenticator> {
    listener: TcpListener,
    config: Arc<Config<A>>,
}

#[derive(Debug)]
struct Socks5Comm<A: Authenticator> {
    socket: TcpStream,
    config: Arc<Config<A>>,
}

#[derive(Debug)]
enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for SocksCommand {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SocksCommand::Connect),
            0x02 => Ok(SocksCommand::Bind),
            0x03 => Ok(SocksCommand::UdpAssociate),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Addr {
    Domain((String, u16)),
    Ip(SocketAddr),
}

pub enum Atyp {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03, 
}

impl From<&Addr> for Atyp {
    fn from(value: &Addr) -> Self {
        match value {
            Addr::Domain((_, _)) => Atyp::Domain, 
            Addr::Ip(sock) => {
                match sock {
                    SocketAddr::V4(_) => Atyp::Ipv4, 
                    SocketAddr::V6(_) => Atyp::Ipv6
                }
            }
        }
    }
}

impl ToSocketAddrs for Addr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match self {
            Addr::Domain((addr, port)) => format!("{}:{}", addr, port).to_socket_addrs(),
            Addr::Ip(ip) => Ok(vec![*ip].into_iter()),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ReplyStatus {
    Succeeded = 0x00,
    GeneralSocksFailure = 0x01, 
    ConnectionNotAllowedByRuleset = 0x02, 
    NetworkUnreacheable = 0x03, 
    HostUnreacheable = 0x04,
    ConnectionRefused = 0x05, 
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl<A: Authenticator> Socks5Comm<A> {
    fn serve(mut self) {
        info!("Received SOCKS connection from {}", self.socket.peer_addr().unwrap()); 

        if let Err(err) = self.greet() {
            debug!("Greet error: {}", err); 
            return; 
        }

        if let Err(err) = self.config.auth.authenticate(&mut self.socket) {
            debug!("Auth error: {}", err);
            return; 
        }

        match self.request() {
            Ok((cmd, addr)) => {
                match cmd {
                    SocksCommand::Connect => {
                        self.connect(addr).ok();
                    }
                    SocksCommand::Bind => {
                        match addr {
                            Addr::Ip(socket) => {
                                self.bind(socket).ok();
                            },
                            Addr::Domain((_, _)) => {
                                debug!("Got domain as address on bind ");
                                return
                            },
                        } 
                    }
                    SocksCommand::UdpAssociate => {
                        todo!();
                    }
                }
            }
            Err(err) => {
                debug!("Request error: {}", err); 
            }
        }
    }

    fn greet(&mut self) -> Result<(), Socks5Error> {
        let mut ver: u8 = 0;
        read_byte!(self.socket, ver)?;
        if ver != 0x05 {
            return Err(Socks5Error::InvalidVersion(ver));
        }

        let mut nauth: u8 = 0;
        read_byte!(self.socket, nauth)?;

        let mut auth: Vec<u8> = vec![0; nauth as usize];
        self.socket.read_exact(&mut auth)?;
        
        debug!("Greeting:
            ver:{}
            nauth:{}
            auth:{:?}
        ", ver, nauth, auth);

        let answer: [u8; 2];
        if auth.contains(&(A::METHOD as u8)) {
            answer = [0x05, A::METHOD as u8];
            self.socket.write_all(&answer)?;
            debug!("Greeting Ok");
            return Ok(());
        } else {
            answer = [0x05, 0xff];
            self.socket.write_all(&answer)?;
            debug!("Greeting Fail"); 
            return Err(Socks5Error::NonSupportedAuth);
        }
    }

    fn request(&mut self) -> SocksResult<(SocksCommand, Addr)> {
        let [ver, cmd, rsv, atyp] = read_bytes!(self.socket, 4);
        if ver != 0x05 {
            debug!("Invalid ver at req, ver: {}", ver);
            return Err(Socks5Error::InvalidVersion(ver));
        }
        let cmd = SocksCommand::try_from(cmd).map_err(|_| Socks5Error::InvalidCommand)?;

        let mut addr: Addr;

        match atyp {
            0x01 => {
                if !self.config.ipv4 {
                    return Err(Socks5Error::Ipv4Disabled);
                }
                let mut buf: [u8; 4] = [0; 4];
                self.socket.read_exact(&mut buf)?;
                let ip = Ipv4Addr::from(buf);
                addr = Addr::Ip(SocketAddr::new(IpAddr::V4(ip), 0));
            }
            0x02 => {
                if !self.config.resolve_dns {
                    return Err(Socks5Error::ResolveDnsDisabled);
                }
                let mut dlen = 0;
                read_byte!(self.socket, dlen)?;
                let mut domain: Vec<u8> = vec![0; dlen as usize];
                self.socket.read_exact(&mut domain)?;
                let domain = String::from_utf8_lossy(&domain);
                addr = Addr::Domain((domain.deref().to_string(), 0));
            }
            0x03 => {
                if !self.config.ipv6 {
                    return Err(Socks5Error::Ipv6Disabled);
                }
                let mut buf: [u8; 16] = [0; 16];
                self.socket.read_exact(&mut buf)?;
                let ip = Ipv6Addr::from(buf);
                addr = Addr::Ip(SocketAddr::new(IpAddr::V6(ip), 0));
            }
            _ => return Err(Socks5Error::InvalidCommand),
        }

        let [d1, d2] = read_bytes!(self.socket, 2);
        let dst_port: u16 = ((d1 as u16) << 8) | (d2 as u16);

        match &mut addr {
            Addr::Ip(ip) => ip.set_port(dst_port),
            Addr::Domain((_, port)) =>  *port = dst_port,
        };

        debug!("Request: 
            ver:{}
            cmd:{:?}
            rsv:{}
            atyp:{}
            addr:{:?}
            port:{}
        ",
        ver,
        cmd,
        rsv,
        atyp,
        addr,
        dst_port);

        self.reply(ReplyStatus::Succeeded, addr.clone())?;

        Ok((cmd, addr))
    }
    
    fn reply(&mut self, rep: ReplyStatus, addr: Addr) -> SocksResult<()> {
        let atyp = Atyp::from(&addr);
        let (bytes_addr, bytes_port) = match addr {
            Addr::Ip(socket) => {
                match socket.ip() {
                    IpAddr::V4(ip) => (u32::from(ip).to_be_bytes().to_vec(), socket.port().to_be_bytes()),
                    IpAddr::V6(ip) => (u128::from(ip).to_be_bytes().to_vec(), socket.port().to_be_bytes())
                }
            },
            Addr::Domain((domain, port)) => (domain.as_bytes().to_vec(), port.to_be_bytes())
        };

        let mut reply = vec![0x05, rep as u8, 0x00, atyp as u8]; 
        reply.extend_from_slice(&bytes_addr);
        reply.extend_from_slice(&bytes_port);

        self.socket.write_all(&reply)?; 

        Ok(())
    }
    
    fn pipe(self, alpha: TcpStream) -> SocksResult<()> {
        let addr = self.socket.peer_addr().unwrap(); 

        let mut target_tx = alpha;
        let mut target_rx = target_tx.try_clone()?;

        let mut source_rx = self.socket;
        let mut source_tx = source_rx.try_clone()?;

        thread::spawn(move || {
            return std::io::copy(&mut target_tx, &mut source_rx);
        });
        
        std::io::copy(&mut source_tx, &mut target_rx)?;
        
        info!("Ending socks connection from {}", addr);

        return Ok(());
    }

    fn connect(self, addr: Addr) -> SocksResult<()> {
        let stream = TcpStream::connect(addr)?;
        self.pipe(stream)        
    }
    
    fn bind(mut self, addr: SocketAddr) -> SocksResult<()> {
        let listener = TcpListener::bind((self.config.socket_address.ip(), 0))?;     

        let listener_addr = SocketAddr::from((self.config.socket_address.ip(), listener.local_addr().unwrap().port()));
        self.reply(ReplyStatus::Succeeded, Addr::Ip(listener_addr))?;

        let (stream, client_addr) = listener.accept().unwrap(); 
        if client_addr.ip() != addr.ip() {
            self.reply(ReplyStatus::GeneralSocksFailure, Addr::Ip(listener_addr))?;
            return Err(Socks5Error::BindDstMismatach((addr.ip(), client_addr.ip())))
        }

        self.reply(ReplyStatus::Succeeded, Addr::Ip(addr))?;

        self.pipe(stream)
    }
    
    #[allow(dead_code)]
    fn udp_associate(&self, _addr: Addr) -> SocksResult<()> {
       todo!() 
    }

}


impl<A: Authenticator + 'static> SocksServer<A> {
    pub fn new(config: Config<A>) -> Result<SocksServer<A>, std::io::Error> {
        let listener = TcpListener::bind(config.socket_address)?;
        Ok(SocksServer {
            listener,
            config: Arc::new(config),
        })
    }

    pub fn serve(self) {
        loop {
            let (socket, _client_addr) = self.listener.accept().unwrap();
            let comm = Socks5Comm {
                socket,
                config: self.config.clone(),
            };
            thread::spawn(move || comm.serve());
        }
    }
}
