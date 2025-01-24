# tlp-genome-rs

Get sample `.fasta` file:

```sh
curl https://ftp.uniprot.org/pub/databases/uniprot/current_release/knowledgebase/complete/uniprot_sprot_varsplic.fasta.gz -o data/uniprot_sprot_varsplic.fasta.gz

gzip --decompress data/uniprot_sprot_varsplic.fasta.gz # outputs data/uniprot_sprot_varsplic.fasta
```

Sample files are found in `data/`:

- `data.txt` original file, expected to be only ascii. 
- `data.mod` modified file, with removal of punctuation ('",. etc), and letters in uppercase. 
- `data.cod` codified file
  - done via directives like:
    - '#unisprot_sprot_varsplic.fasta,10,2'
    - '#filename,initial_offset,max_file_loop_attempts'

Usage:

```sh
cargo run --release -- data/text1.txt
# will output:
# - data/text1.mod
# - data/text1.cod
```

Rust installation instructions (to use `cargo`): <https://www.rust-lang.org/tools/install>.
