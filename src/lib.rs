//! #### MCCP2
//! A feature of some telnet servers is `MCCP2` which allows the downstream data to be compressed.
//! To use this, first enable the `zcstream` [rust feature](https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section) for this crate.
//! Then in the code deal with the relevant events, and switch the zlib when appropriate.
//!
//! Basic usage example:
//! ```ignore
//! match event {
//! 	TelnetEvent::Data(buffer) => {
//! 		println!("{}", &std::str::from_utf8(&(*buffer)).unwrap());
//! 	},
//! 	TelnetEvent::Negotiation(NegotiationAction::Will, TelnetOption::Compress2) => {
//! 		telnet.negotiate(NegotiationAction::Do, TelnetOption::Compress2);
//! 	},
//! 	TelnetEvent::Subnegotiation(TelnetOption::Compress2, _) => {
//! 		telnet.begin_zlib();
//! 	}
//! }
//! ```
mod negotiation;
mod option;
mod event;
mod byte;
mod stream;
#[cfg(feature = "zcstream")]
mod zcstream;
#[cfg(feature = "zcstream")]
mod zlibstream;

pub use stream::Stream;
#[cfg(feature = "zcstream")]
pub use zlibstream::ZlibStream;
#[cfg(feature = "zcstream")]
pub use zcstream::ZCStream;
pub use option::TelnetOption;
pub use event::TelnetEvent;
pub use negotiation::NegotiationAction;

use std::io;
use std::io::{Read, Write, ErrorKind};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::rc::Rc;
use std::ops::{Deref, DerefMut};

use byte::*;

#[cfg(feature = "zcstream")]
type TStream = zcstream::ZCStream;
#[cfg(not(feature = "zcstream"))]
type TStream = stream::Stream;

#[derive(Debug)]
enum ParsingState {
    NormalData(usize),
    IAC,
    SB,
    SBData(TelnetOption, Vec<u8>, bool),    // option, data, iac
    Negotiation(NegotiationAction),
}

///
/// A telnet connection to a remote host.
///
/// # Examples
/// ```rust,should_panic
/// use telnet::Telnet;
///
/// let mut connection = Telnet::connect(("127.0.0.1", 23), 256)
///         .expect("Couldn't connect to the server...");
/// loop {
///     let event = connection.read().expect("Read Error");
///     println!("{:?}", event);
/// }
/// ```
///
pub struct Parser {
    state: ParsingState,
}

impl Parser {
    #[cfg(feature = "zcstream")]
    pub fn begin_zlib(&mut self) {
        //self.stream.begin_zlib()
    }

    #[cfg(feature = "zcstream")]
    pub fn end_zlib(&mut self) {
        //self.stream.end_zlib()
    }
    /// Open a telnet connection to a remote host using a generic stream.
    /// 
    /// Communication will be made with the host using `stream`. `buf_size` is the size of the underlying
    /// buffer for processing data from the host.
    /// 
    /// Use this version of the constructor if you want to provide your own stream, for example if you want
    /// to mock out the remote host for testing purposes, or want to wrap the data the data with TLS encryption.
    pub fn new() -> Parser {
        Parser {
            state: ParsingState::NormalData(0),
        }
    }

    ///
    /// Reads a `TelnetEvent`.
    ///
    /// If there was not any queued `TelnetEvent`, it would read a chunk of data into its buffer,
    /// extract any telnet command in the message, and queue all processed results. Otherwise, it
    /// would take a queued `TelnetEvent` without reading data from `TcpStream`.
    ///
    /// # Examples
    /// ```rust,should_panic
    /// use telnet::Telnet;
    ///
    /// let mut connection = Telnet::connect(("127.0.0.1", 23), 256)
    ///         .expect("Couldn't connect to the server...");
    /// let event = connection.read().expect("Read Error");
    /// println!("{:?}", event);
    /// ```
    ///
    pub fn parse<'a>(&mut self, buffer: &'a [u8]) -> Events<'a> {
        if let ParsingState::NormalData(data_start) = self.state {
            assert!(data_start == 0);
        }

        let mut events: Vec<TelnetEvent> = (0..buffer.len())
            .filter_map(|i| self.parse_byte(buffer, i))
            .collect();

        if let ParsingState::NormalData(data_start) = self.state {
            if data_start < buffer.len() {
                events.push(TelnetEvent::Data(&buffer[data_start..]));
            }

            // Reset for next call to read
            self.state = ParsingState::NormalData(0);
        }

        events.into()
    }

    fn parse_byte<'a>(&mut self, buffer: &'a [u8], index: usize) -> Option<TelnetEvent<'a>> {
        let byte = buffer[index];

        match self.state {
            // Normal Data
            ParsingState::NormalData(data_start) => {
                if byte == BYTE_IAC {
                    // The following bytes will be commands

                    // Update the state
                    self.state = ParsingState::IAC;

                    // Send the data before this byte
                    if data_start < index {
                        return Some(TelnetEvent::Data(&buffer[data_start..index]));
                    }
                }
            },

            // Telnet Commands
            ParsingState::IAC => {
                let mut err = false;

                self.state = match byte {
                    // Negotiation Commands
                    BYTE_WILL => ParsingState::Negotiation(NegotiationAction::Will),
                    BYTE_WONT => ParsingState::Negotiation(NegotiationAction::Wont),
                    BYTE_DO => ParsingState::Negotiation(NegotiationAction::Do),
                    BYTE_DONT => ParsingState::Negotiation(NegotiationAction::Dont),
                    // Subnegotiation
                    BYTE_SB => ParsingState::SB,
                    // Escaping
                    // TODO: Write a test case for this
                    BYTE_IAC => ParsingState::NormalData(index),
                    // Unknown IAC commands
                    _ => {
                        err = true;
                        ParsingState::NormalData(index+1)
                    }
                };

                if err {
                    return Some(TelnetEvent::UnknownIAC(byte));
                }
            },

            // Negotiation
            ParsingState::Negotiation(action) => {
                self.state = ParsingState::NormalData(index+1);
                let opt = TelnetOption::parse(byte);
                return Some(TelnetEvent::Negotiation(action, opt));
            },

            // Start subnegotiation
            ParsingState::SB => {
                let opt = TelnetOption::parse(byte);
                self.state = ParsingState::SBData(opt, Vec::new(), false);
            },

            // Subnegotiation's data
            ParsingState::SBData(opt, ref mut data, ref mut iac) => {
                if *iac {
                    // IAC inside Subnegotiation's data
                    *iac = false;

                    match byte {
                        // The end of subnegotiation
                        BYTE_SE => {
                            let data_boxed = data.clone().into();
                            self.state = ParsingState::NormalData(index+1);
                            return Some(TelnetEvent::Subnegotiation(opt, data_boxed));
                        },
                        // Escaping
                        // TODO: Write a test case for this
                        BYTE_IAC => data.push(BYTE_IAC),
                        // TODO: Write a test case for this
                        b => return Some(TelnetEvent::Error(format!("Unexpected byte after IAC inside SB: {}", b))),
                    }
                } else {
                    if byte == BYTE_IAC {
                        *iac = true;
                    } else {
                        data.push(byte);
                    }
                }
            },
        }

        None
    }
}

fn format_internal(mut buffer: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let mut start = 0;

    for i in 0..data.len() {
        if data[i] == BYTE_IAC {
            buffer.extend_from_slice(&data[start..(i+1)]);
            start = i;
        }
    }

    if start < data.len() {
        buffer.extend_from_slice(&data[start..]);
    }

    buffer
}

///
/// Writes a given data block to the remote host. It will double any IAC byte.
///
/// # Examples
/// ```rust,should_panic
/// use telnet::Telnet;
///
/// let mut connection = Telnet::connect(("127.0.0.1", 23), 256)
///         .expect("Couldn't connect to the server...");
/// let buffer: [u8; 4] = [83, 76, 77, 84];
/// connection.write(&buffer).expect("Write Error");
/// ```
///
pub fn format(data: &[u8]) -> Box<[u8]> {
    format_internal(Vec::new(), data).into()
}

///
/// Negotiates a telnet option with the remote host.
///
/// # Examples
/// ```rust,should_panic
/// use telnet::{Telnet, NegotiationAction, TelnetOption};
///
/// let mut connection = Telnet::connect(("127.0.0.1", 23), 256)
///         .expect("Couldn't connect to the server...");
/// connection.negotiate(NegotiationAction::Will, TelnetOption::Echo);
/// ```
///
pub fn format_negotiate(action: NegotiationAction, opt: TelnetOption) -> Box<[u8]> {
    Box::new([BYTE_IAC, action.to_byte(), opt.to_byte()])
}

///
/// Send data for sub-negotiation with the remote host.
///
/// # Examples
/// ```rust,should_panic
/// use telnet::{Telnet, NegotiationAction, TelnetOption};
///
/// let mut connection = Telnet::connect(("127.0.0.1", 23), 256)
///         .expect("Couldn't connect to the server...");
/// connection.negotiate(NegotiationAction::Do, TelnetOption::TTYPE);
/// let data: [u8; 1] = [1];
/// connection.subnegotiate(TelnetOption::TTYPE, &data);
/// ```
///
pub fn format_subnegotiate(opt: TelnetOption, data: &[u8]) -> Box<[u8]> {
    let mut buf = format_internal(vec![BYTE_IAC, BYTE_SB, opt.to_byte()], data);
    buf.extend_from_slice(&[BYTE_IAC, BYTE_SE]);
    buf.into()
}

pub struct Events<'a> {
    inner: std::vec::IntoIter<TelnetEvent<'a>>,
}

impl<'a> From<Vec<TelnetEvent<'a>>> for Events<'a> {
    fn from(events: Vec<TelnetEvent<'a>>) -> Self {
        Self { inner: events.into_iter() }
    }
}

impl<'a> Iterator for Events<'a> {
    type Item = TelnetEvent<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

pub struct Reader<R: Read> {
    parser: Parser,
    reader: R,
    buffer: Box<[u8]>,
}

impl<R: Read> Reader<R> {
    pub fn new(reader: R, capacity: usize) -> Self {
        Self {
            parser: Parser::new(),
            reader,
            buffer: vec![0; capacity].into(),
        }
    }

    pub fn read(&mut self) -> io::Result<Events> {
        let n = self.reader.read(self.buffer.as_mut())?;
        Ok(self.parser.parse(&self.buffer[..n]))
    }
}

pub fn write_once<T, F: FnOnce(&[u8]) -> Result<usize, T>>(buf: &[u8], write: F) -> Result<usize, T> {
    if buf.len() == 0 {
        return Ok(0);
    }

    let first_iac = buf.iter().position(|&x| x == BYTE_IAC).unwrap_or(buf.len());

    if first_iac == 0 {
        write(&[BYTE_IAC, BYTE_IAC]).map(|n| if n == 0 { 0 } else { n-1 })
    } else {
        write(&buf[..first_iac])
    }
}

/*

// tokio::io::AsyncWrite using write_once

fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    let bytes_written = telnet::write_once(buf, |b| match self.project().0.poll_write(cx, b) {
        Poll::Ready(Ok(n)) => Ok(n),
        ret => Err(ret),
    });

    match bytes_written {
        Ok(n) => Poll::Ready(Ok(n)),
        Err(ret) => ret,
    }
}

*/

pub struct Writer<W: Write>(W);

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_once(buf, |b| self.0.write(b))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write> Writer<W> {
    pub fn new(writer: W) -> Self {
        Self(writer)
    }

    pub fn negotiate(&mut self, action: NegotiationAction, opt: TelnetOption) -> io::Result<()> {
        let buf = format_negotiate(action, opt);
        self.0.write_all(&buf)
    }
    
    pub fn subnegotiate(&mut self, opt: TelnetOption, data: &[u8]) -> io::Result<()> {
        let buf = format_subnegotiate(opt, data);
        self.0.write_all(&buf)
    }
}

/* 

USAGE

let mut stream = TcpStream::connect(("127.0.0.1", 5555))?;

let neg_buf = format_negotiate(NegotiationAction::Will, TelnetOption::TransmitBinary);
stream.write_all(&neg_buf)?;

let mut buffer = [0u8; 256];
loop {
    let n = stream.read(&mut buffer)?;
    for event in reader.read(&buffer[..n]) {
        match event {
            ...
        }
    }
}

*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::ops::Deref;

    struct MockStream {
        test_data: Vec<u8>
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> MockStream {
            MockStream {
                test_data: data,
            }
        }
    }

    impl stream::Stream for MockStream {
        fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), Error> {
            return Ok(())
        }

        fn set_read_timeout(&self, _dur: Option<Duration>) -> Result<(), Error> {
            return Ok(())
        }
    }

    impl io::Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut offset = 0;
            while offset < buf.len() && offset < self.test_data.len() {
                buf[offset] = self.test_data[offset];
                offset += 1;
            }
            return Ok(offset);
        }
    }

    impl io::Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            return Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            return Ok(())
        }
    }

    #[test]
    fn escapes_double_iac_correctly() {
        let stream = MockStream::new(vec!(0x40, 0x5a, 0xff, 0xff, 0x31, 0x34));
        #[cfg(feature = "zcstream")]
        let stream = ZlibStream::from_stream(stream);
        let stream = Box::new(stream);

        let mut telnet = Parser::from_stream(stream, 6);

        let expected_bytes_1: [u8;2] = [0x40, 0x5a];
        let expected_bytes_2: [u8;3] = [0xff, 0x31, 0x34];

        let event_1 = telnet.read_nonblocking().unwrap();
        match event_1 {
            TelnetEvent::Data(buffer) => {
                assert_eq!(buffer.deref(), &expected_bytes_1);
            },
            _ => {
                assert!(false);
            }
        }

        let event_2 = telnet.read_nonblocking().unwrap();
        match event_2 {
            TelnetEvent::Data(buffer) => {
                assert_eq!(buffer.deref(), &expected_bytes_2);
            },
            _ => {
                assert!(false);
            }
        }
    }
}
