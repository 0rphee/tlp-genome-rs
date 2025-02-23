import sys

def process_file(filename):
    try:
        max_ascii_overall = float('-inf')
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line.startswith('>'):
                    max_ascii = max(ord(char) for char in line)
                    max_ascii_overall = max(max_ascii_overall, max_ascii)
        if max_ascii_overall != float('-inf'):
            print(f"Max ASCII value across all lines: {max_ascii_overall}")
        else:
            print("No valid lines found.")
    except FileNotFoundError:
        print("Error: File not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
    else:
        filename = sys.argv[1]
        process_file(filename)