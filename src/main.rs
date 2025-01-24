use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{self};
use std::time::Instant;

fn main() -> () {
    let start_time: Instant = Instant::now();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <filepath>", args[0]); // args[0]: name of exe
        process::exit(1);
    }

    let source_filepath = Path::new(&args[1]);

    match fs::read_to_string(source_filepath) {
        Err(err) => {
            eprintln!("Failed to open file '{:?}': {}", source_filepath, err);
            process::exit(1);
        }
        Ok(str) => encrypt_bytes(source_filepath, str),
    }

    let duration = start_time.elapsed();
    println!("File encrypted in: {:?}", duration);
    println!("File encrypted in seconds: {:?}", duration.as_secs_f32());
    process::exit(0);
}

static DEFAULT_ALPHA_ARR: [u8; 26] = [
    0,    // 0   A
    b'Z', // 1   B
    0,    // 2   C
    0,    // 3   D
    0,    // 4   E
    0,    // 5   F
    0,    // 6   G
    0,    // 7   H
    0,    // 8   I
    b'X', // 9   J
    0,    // 10  K
    0,    // 11  L
    0,    // 12  M
    0,    // 13  N
    b'U', // 14  O
    0,    // 15  P
    0,    // 16  Q
    0,    // 17  R
    0,    // 18  S
    0,    // 19  T
    b'O', // 20  U
    0,    // 21  V
    0,    // 22  W
    b'J', // 23  X
    0,    // 24  Y
    b'B', // 25  Z
];

#[derive(Debug)]
struct KeyFileData {
    first_offset: u16,
    key_path: PathBuf,
    line_index: usize,
    max_attempts: u16,
}

enum AttemptsResult {
    MaxReached,
    NotReached,
}

impl<'a> KeyFileData {
    fn fill_alpha_arr(&self, alpha_arr: &mut [u8; 26]) -> AttemptsResult {
        fn get_second_offset(
            first_offset: u16,
            attempt_count: &mut u16,
            max_attempts: u16,
            bytes: &[u8],
        ) -> Option<u8> {
            {
                let mut current_offset_left = first_offset;
                let mut in_header = false;
                loop {
                    for byte in bytes.iter() {
                        match byte {
                            b'>' => {
                                in_header = true;
                                current_offset_left -= 1;
                            }
                            b'\n' => in_header = false,
                            _ => {
                                if in_header {
                                    if current_offset_left == 0 {
                                        return Some(*byte);
                                    }
                                    current_offset_left -= 1
                                }
                            }
                        }
                    }
                    if current_offset_left > 0 {
                        *attempt_count += 1;
                        if *attempt_count >= max_attempts {
                            eprintln!("Max attempts reached {}, cannot encrypt.", max_attempts);
                            process::exit(1);
                        }
                    }
                }
            }
        }
        fn mutate_alpha_array(
            second_offset: u8,
            max_attempts: u16,
            bytes: &[u8],
            alpha_arr: &mut [u8; 26],
            attempt_count: &mut u16,
        ) -> AttemptsResult {
            // find array mappings
            // we only need to check the mappings for the 20 letters that don't have a fixed substitution value
            let mut already_used_values: HashSet<u8, _> = HashSet::with_capacity(20);
            let mut next_item_alpha_arr_index = 0;
            {
                let mut current_offset_left2 = second_offset;
                let mut in_header = false;
                loop {
                    for byte in bytes.iter() {
                        match byte {
                            b'>' => in_header = true,
                            b'\n' => in_header = false,
                            b'Z' | b'X' | b'J' | b'U' | b'O' | b'B' => {
                                current_offset_left2 = second_offset;
                            }
                            _ => {
                                if in_header {
                                    continue;
                                };
                                if current_offset_left2 == 0 {
                                    if already_used_values.contains(byte) {
                                        current_offset_left2 = second_offset;
                                        continue;
                                    }
                                    already_used_values.insert(*byte);
                                    alpha_arr[next_item_alpha_arr_index] = *byte;
                                    next_item_alpha_arr_index += 1;
                                    match next_item_alpha_arr_index {
                                        1 | 9 | 14 | 20 | 23 => next_item_alpha_arr_index += 1,
                                        25 => break,
                                        _ => (),
                                    }
                                    current_offset_left2 = second_offset;
                                }
                                current_offset_left2 -= 1
                            }
                        }
                    }
                    if already_used_values.len() == 20 {
                        return AttemptsResult::NotReached;
                    } else {
                        *attempt_count += 1;
                        if *attempt_count >= max_attempts {
                            return AttemptsResult::MaxReached;
                        }
                    }
                }
            }
        }
        // function body
        let mut attempt_count = 0;
        let bytes = fs::read(&self.key_path).unwrap();
        let second_offset = match get_second_offset(
            self.first_offset,
            &mut attempt_count,
            self.max_attempts,
            &bytes,
        ) {
            Some(v) => v,
            None => return AttemptsResult::MaxReached,
        };

        let max_attempts_reached = mutate_alpha_array(
            second_offset,
            self.max_attempts,
            &bytes,
            alpha_arr,
            &mut attempt_count,
        );
        #[cfg(debug_assertions)]
        {
            let char_vec: Vec<_> = alpha_arr
                .iter()
                .enumerate()
                .map(|(i, v)| (i, char::from(*v)))
                .collect();
            println!("Arr filled: {:?}", char_vec);
        }
        return max_attempts_reached;
    }
}

fn encrypt_bytes(source_filepath: &Path, bytes: String) -> () {
    fn writer_helper(writer: &mut BufWriter<File>, line: &str) {
        if let Err(err) = writeln!(writer, "{}", line) {
            eprintln!("Failed to write to file: {}", err);
            process::exit(1);
        }
        #[cfg(debug_assertions)]
        println!("written line: {}", line);
    }
    let mut alpha_arr: [u8; 26] = DEFAULT_ALPHA_ARR;
    let mut keyfile_vec: Vec<_> = Vec::new();

    // Create .mod file (uppercase & without punctuation)
    let mod_filepath = source_filepath.with_extension("mod");
    let mod_file = File::create(&mod_filepath).unwrap_or_else(|err| {
        eprintln!("Failed to create output file: {}", err);
        process::exit(1);
    });
    let mut mod_writer = BufWriter::new(mod_file);

    // Create .cod file (substituded letters from array)
    let cod_filepath = source_filepath.with_extension("cod");
    let cod_file = File::create(&cod_filepath).unwrap_or_else(|err| {
        eprintln!("Failed to create output file: {}", err);
        process::exit(1);
    });
    let mut cod_writer = BufWriter::new(cod_file);

    let lines = bytes.lines().map(|v| v.trim());
    for (lnum, line) in lines.enumerate() {
        if line.starts_with("#") {
            let splt: Vec<_> = line.splitn(3, ',').collect();
            let key_path = source_filepath.parent().unwrap().join(&splt[0][1..]);

            let key = KeyFileData {
                key_path,
                first_offset: splt[1].parse().unwrap(),
                max_attempts: splt[2].parse().unwrap(),
                line_index: lnum,
            };
            #[cfg(debug_assertions)]
            println!("{:?}", key);

            if let AttemptsResult::MaxReached = key.fill_alpha_arr(&mut alpha_arr) {
                eprintln!("Max attempts reached, cannot encrypt.");
                process::exit(1);
            }
            keyfile_vec.push(key);
            writer_helper(&mut mod_writer, line);
            writer_helper(&mut cod_writer, line);
        } else {
            let upper: String = line
                .chars()
                .filter_map(|c| {
                    if c.is_ascii_punctuation() {
                        Option::None
                    } else {
                        Option::Some(c.to_ascii_uppercase())
                    }
                })
                .collect();
            let codified: String = upper
                .bytes()
                .map(|byte| -> char {
                    if byte == b' ' {
                        byte.into()
                    } else {
                        // we assume every byte now is an ascii letter
                        alpha_arr[(byte - b'A') as usize].into()
                    }
                })
                .collect();
            writer_helper(&mut mod_writer, &upper);
            writer_helper(&mut cod_writer, &codified);
        }
    }
    // Flush buffer to ensure all data is written to the file
    if let Err(err) = mod_writer.flush() {
        eprintln!("Failed to flush buffer: {}", err);
        process::exit(1);
    }

    // // Reopen the modified file for reading
    // let mod_file = match File::open(&mod_filepath) {
    //     Ok(file) => file,
    //     Err(err) => {
    //         eprintln!("Failed to open modified file for reading: {}", err);
    //         process::exit(1);
    //     }
    // };
    // let mod_reader = BufReader::new(mod_file);

    // // Read the modified file line by line
    // for line in mod_reader.lines() {
    //     match line {
    //         Ok(_line) => {
    //             println!("Read from modified file: {}", _line)
    //         }
    //         Err(err) => {
    //             eprintln!("Failed to read line from modified file: {}", err);
    //             process::exit(1);
    //         }
    //     }
    // }
}
