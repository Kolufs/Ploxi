#[macro_export()]
macro_rules! read_bytes {
    ($reader:expr, $count:expr) => {{
        let mut buffer = [0u8; $count];

        $reader.read_exact(&mut buffer)?;
        buffer
    }};
}

#[macro_export()]
macro_rules! read_byte {
    ($reader: expr, $byte: expr) => {{
        $reader.read(std::slice::from_mut(&mut $byte))
    }};
}
