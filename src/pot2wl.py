#!/usr/bin/env python

#   Name........: pot2wl.py
#   Author......: Hash Republic <hashrepublic@gmail.com>
#   License.....: MIT
 
import sys
import argparse

def print_progress_bar(iteration, total, length=40):
    percent = (iteration / total) * 100
    bar_length = int(length * percent // 100)
    bar = '#' * bar_length + '-' * (length - bar_length)
    sys.stdout.write(f'\r-> |{bar}| {percent:.2f}% Complete')
    sys.stdout.flush()

def hex_to_string(input):
    if input.startswith('$HEX[') and input.endswith(']'):
        hex_part = input[5:-1]
        try:
            decoded_string = bytes.fromhex(hex_part).decode('ISO-8859-1')
            return decoded_string
        except ValueError:
            return input
    else:
        return input

def keep_after_last_colon(input_string):
    last_colon_index = input_string.rfind(':') 
    if last_colon_index != -1:
        return input_string[last_colon_index + 1:].strip()
    return input_string.strip()

def main():
    parser = argparse.ArgumentParser(description="Example program to parse flags.")
    parser.add_argument('--input', type=str, required=True, help='Input file name')
    parser.add_argument('--output', type=str, help='Output file name')
    parser.add_argument('--unhex', action='store_true', help='Unhex the input data')
    parser.add_argument('--sort', action='store_true', help='Sort by occurences descending (slower)')
    args = parser.parse_args()

    word_count = {}
    outfile = None
    if args.output:
        outfile = open(args.output, 'w')

    with open(args.input, 'r') as infile:
        total_lines = sum(1 for _ in infile)        
        infile.seek(0)  
        if args.sort: 
            print("-> Generating dict ...")
            print_progress_bar(0, total_lines)            
        for i, line in enumerate(reversed(list(infile))):
            r = keep_after_last_colon(line)
            if args.unhex:  
                r = hex_to_string(r)
            if args.sort:
                if r in word_count:
                    word_count[r] += 1
                else: 
                    word_count[r] = 1
                print_progress_bar(i+1 , total_lines)
            else: 
                if outfile is None:
                    print(r)
                else:
                    outfile.write(r + "\n")

    if args.sort: 
        print("")
        print("-> Sorting dict ...")
        sorted_word_count = sorted(word_count.items(), key=lambda item: item[1], reverse=True)
        print("-> Complete")
        for r, count in sorted_word_count:
            if outfile is None:
                print(r)
            else:
                outfile.write(r + "\n")

    if outfile is not None:
        outfile.close()

if __name__ == "__main__":
    main()