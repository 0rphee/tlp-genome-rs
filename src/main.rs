use core::panic;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::mem::{transmute, MaybeUninit};
use std::path::{Path, PathBuf};
use std::process::{self};
use std::time::Instant;
use std::{env, io};

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
    max_attempts: u16,
}

#[derive(Debug)]
enum AttemptsResult {
    MaxReached,
    NotReached,
}

struct ChunkReader {
    bytes_buff: Vec<u8>,
    file: File,
    file_size: u64,
    file_read_bytes: usize,
}

/*
1. reader creation: initial read of x KB
2. the user reads through the initial read bytes
3. when the initial part of the file is finished, another batch of x KB (or the rest of the file if the rest is less than x KB)
4. repeat, until all the file is finished.
*/

impl ChunkReader {
    // max ascii value in '>' lines in *.fasta files: 124
    //   see: test.py, run against any *.fasta file
    //   ex. 'python3 test.py data/uniprot_sprot_varsplic.fasta'
    // chunk size used when reading a file into memory in parts
    // 1024 bytes = 1 KB
    // 124*25 = 3,100; 3100 / 1024
    const CHUNK_SIZE: usize = 15 * 1024;
    fn new(file: File) -> ChunkReader {
        #[cfg(debug_assertions)]
        println!("New chunk reader");
        let file_size = file.metadata().expect("File size").len();
        let mut reader = ChunkReader {
            bytes_buff: Vec::with_capacity(0),
            file,
            file_size,
            file_read_bytes: 0,
        };
        reader.load_next_chunk().expect("Read bytes");
        return reader;
    }

    fn load_next_chunk(&mut self) -> io::Result<usize> /* bytes loaded */ {
        let rest_of_file_size = self.file_size as usize - self.file_read_bytes;
        let next_chunk_size = if rest_of_file_size > Self::CHUNK_SIZE {
            Self::CHUNK_SIZE
        } else {
            rest_of_file_size
        };

        self.bytes_buff.reserve_exact(next_chunk_size);

        let spare_capacity_slice: &mut [u8] = unsafe {
            transmute::<&mut [MaybeUninit<u8>], &mut [u8]>(self.bytes_buff.spare_capacity_mut())
        };
        let bytes_read = self.file.read(spare_capacity_slice)?;

        #[cfg(debug_assertions)]
        println!(
            "Loading next chunk: next_chunk_size {}, bytes_read {}",
            next_chunk_size, bytes_read
        );

        unsafe { self.bytes_buff.set_len(self.bytes_buff.len() + bytes_read) };
        self.file_read_bytes += bytes_read;

        if self.bytes_buff.len() > self.bytes_buff.capacity() {
            panic!("Error with loading next chunk");
        }
        return Ok(bytes_read);
    }
    fn is_finished_loading_file(&self) -> bool {
        return self.file_read_bytes >= self.file_size as usize;
    }
    fn iter<'a>(&'a mut self) -> ReaderIter<'a> {
        ReaderIter::new(self)
    }
    fn iter_at<'a>(&'a mut self, index_start: usize) -> ReaderIter<'a> {
        ReaderIter::new_at(self, index_start)
    }
}

struct ReaderIter<'a> {
    index: usize,
    reader: &'a mut ChunkReader,
}
impl<'a> ReaderIter<'a> {
    fn new(reader: &'a mut ChunkReader) -> ReaderIter<'a> {
        ReaderIter { index: 0, reader }
    }
    fn new_at(reader: &'a mut ChunkReader, index_start: usize) -> ReaderIter<'a> {
        ReaderIter {
            index: index_start,
            reader,
        }
    }
}

impl<'a> Iterator for ReaderIter<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        // if the iterator is at the end of buffer read another data chunk from the file
        if self.index == self.reader.bytes_buff.len() - 1 {
            #[cfg(debug_assertions)]
            println!(
                "ReaderIter index at end of buffer: {} ix: {}",
                self.reader.bytes_buff[self.index] as char, self.index
            );
            if self.reader.is_finished_loading_file() {
                return None;
            };
            if self.reader.load_next_chunk().expect("Bytes read") == 0 {
                return None;
            }
        }
        let val = *self
            .reader
            .bytes_buff
            .get(self.index)
            .expect("bytes_buff get index");
        self.index += 1;
        return Some(val);
    }
}

fn get_second_offset(
    first_offset: u16,
    attempt_count: &mut u16,
    max_attempts: u16,
    byte_reader: &mut ChunkReader,
) -> Option<(u8, usize)> {
    // let mut index = 0;
    let mut current_offset_left = 0;
    let mut in_header = false;
    loop {
        for (ix, byte) in byte_reader.iter().enumerate() {
            match byte {
                b'>' => {
                    in_header = true;
                    current_offset_left += 1;
                }
                b'\n' => in_header = false,
                b'\r' => continue,
                _ => {
                    if in_header {
                        if current_offset_left == first_offset {
                            #[cfg(debug_assertions)]
                            println!("second offset {} ({}) at {}", byte as char, byte, ix);
                            return Some((byte, ix));
                        }
                        current_offset_left += 1
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
fn mutate_alpha_array(
    second_offset: u8,
    prev_ix: usize,
    max_attempts: u16,
    byte_reader: &mut ChunkReader,
    alpha_arr: &mut [u8; 26],
    attempt_count: &mut u16,
) -> AttemptsResult {
    // find array mappings
    // we only need to check the mappings for the 20 letters that don't have a fixed substitution value
    let mut already_used_values: HashSet<u8, _> = HashSet::with_capacity(20);
    let mut next_item_alpha_arr_index = 0;
    let mut current_offset_left2 = 1;
    let mut in_header = true;
    let mut start_position = prev_ix;
    loop {
        for (ix, byte) in byte_reader.iter_at(start_position).enumerate() {
            match byte {
                b'>' => in_header = true,
                b'\r' => continue,
                b'\n' => in_header = false,
                b'Z' | b'X' | b'J' | b'U' | b'O' | b'B' => {
                    current_offset_left2 = 1;
                }
                _ => {
                    if in_header {
                        continue;
                    };
                    if current_offset_left2 == second_offset {
                        if already_used_values.contains(&byte) {
                            current_offset_left2 = 1;
                            continue;
                        }
                        #[cfg(debug_assertions)]
                        println!(
                            "inserted: {} offset at: {}",
                            byte as char, current_offset_left2
                        );

                        already_used_values.insert(byte);
                        alpha_arr[next_item_alpha_arr_index] = byte;
                        next_item_alpha_arr_index += 1;
                        match next_item_alpha_arr_index {
                            1 | 9 | 14 | 20 | 23 => next_item_alpha_arr_index += 1,
                            25 => {
                                #[cfg(debug_assertions)]
                                println!("End position: {} ({})", byte as char, ix);
                                break;
                            }
                            _ => (),
                        }
                        current_offset_left2 = 1;
                        continue;
                    }
                    #[cfg(debug_assertions)]
                    println!(
                        "curr byte: {} offset at: {}",
                        byte as char, current_offset_left2
                    );

                    current_offset_left2 += 1
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
            start_position = 0;
        }
    }
}

impl<'a> KeyFileData {
    fn fill_alpha_arr(&self, alpha_arr: &mut [u8; 26]) -> AttemptsResult {
        let f = File::open(&self.key_path).unwrap();
        let mut reader = ChunkReader::new(f);
        let mut attempt_count = 0;

        let (second_offset, prev_ix) = match get_second_offset(
            self.first_offset,
            &mut attempt_count,
            self.max_attempts,
            &mut reader,
        ) {
            Some(v) => v,
            None => return AttemptsResult::MaxReached,
        };

        #[cfg(debug_assertions)]
        println!("mutate_alpha_array");
        let max_attempts_reached = mutate_alpha_array(
            second_offset,
            prev_ix,
            self.max_attempts,
            &mut reader,
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
        if let Err(err) = write!(writer, "{}", line) {
            eprintln!("Failed to write to file: {}", err);
            process::exit(1);
        }
    }
    let mut alpha_arr: [u8; 26] = DEFAULT_ALPHA_ARR;

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

    let lines = bytes.split_inclusive('\n');
    for line in lines {
        if line.starts_with("#") {
            let splt: Vec<_> = line.splitn(3, ',').collect();
            let key_path = source_filepath.parent().unwrap().join(&splt[0][1..]);

            let key = KeyFileData {
                key_path,
                first_offset: splt[1].parse().expect("first offset integer"),
                max_attempts: splt[2]
                    .trim_ascii_end()
                    .parse()
                    .expect("max attemtps integer"),
            };
            #[cfg(debug_assertions)]
            println!("{:?}", key);

            if let AttemptsResult::MaxReached = key.fill_alpha_arr(&mut alpha_arr) {
                eprintln!("Max attempts reached, cannot encrypt.");
                process::exit(1);
            }
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
                    if byte.is_ascii_alphabetic() {
                        // we assume every byte now is an ascii letter
                        alpha_arr[(byte - b'A') as usize].into()
                    } else {
                        byte.into()
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
}
