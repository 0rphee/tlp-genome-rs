use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::process;
use std::time::Instant;

mod parser;

fn main() -> () {
    let start_time: Instant = Instant::now();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <filepath>", args[0]); // args[0]: name of exe
        process::exit(1);
    }

    let source_filepath = &args[1];

    match fs::read_to_string(source_filepath) {
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", source_filepath, err);
            process::exit(1);
        }
        Ok(str) => encrypt_bytes(source_filepath, str),
    }

    let duration = start_time.elapsed();
    println!("File encrypted into: {:?}", duration);
    println!("File encrypted into: {:?}", duration.as_secs_f32());
    process::exit(0);
}

static mut ALPHA_ARR: [u8; 26] = [
    0,    /*A*/
    b'Z', /*B*/
    0,    /*C*/
    0,    /*D*/
    0,    /*E*/
    0,    /*F*/
    0,    /*G*/
    0,    /*H*/
    0,    /*I*/
    b'X', /*J*/
    0,    /*K*/
    0,    /*L*/
    0,    /*M*/
    0,    /*N*/
    b'U', /*O*/
    0,    /*P*/
    0,    /*Q*/
    0,    /*R*/
    0,    /*S*/
    0,    /*T*/
    b'O', /*U*/
    0,    /*V*/
    0,    /*W*/
    b'J', /*X*/
    0,    /*Y*/
    b'Z', /*Z*/
];

enum FillArrSucess {
    Success,
    Failure,
}

#[derive(Debug)]
struct KeyFileData<'a> {
    key_filename: &'a str,
    first_offset: u16,
    max_attempts: u16,
    line_index: usize,
}

fn encrypt_bytes(source_filepath: &str, bytes: String) -> () {
    fn writer_helper(writer: &mut BufWriter<File>, line: &str) {
        if let Err(err) = writeln!(writer, "{}", line) {
            eprintln!("Failed to write to file: {}", err);
            process::exit(1);
        }
    }

    let mut keyfile_vec: Vec<_> = Vec::new();

    // Create a new file to write the modified content
    let mod_file = match File::create(source_filepath.to_owned() + ".mod") {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to create output file: {}", err);
            process::exit(1);
        }
    };
    let mut mod_writer = BufWriter::new(mod_file);

    let lines = bytes.lines().map(|v| v.trim());
    for (lnum, line) in lines.enumerate() {
        if line.starts_with("#") {
            let splt: Vec<_> = line.splitn(3, ',').collect();
            let key = KeyFileData {
                key_filename: &splt[0][1..],
                first_offset: splt[1].parse().unwrap(),
                max_attempts: splt[2].parse().unwrap(),
                line_index: lnum,
            };
            println!("splits:\n {:?}", key);
            keyfile_vec.push(key);

            writer_helper(&mut mod_writer, line);
        } else {
            let upper = line.to_uppercase();
            writer_helper(&mut mod_writer, &upper);
        }
    }
    // Flush buffer to ensure all data is written to the file
    if let Err(err) = mod_writer.flush() {
        eprintln!("Failed to flush buffer: {}", err);
        process::exit(1);
    }
}
