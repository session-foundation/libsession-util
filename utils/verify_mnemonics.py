#!/usr/bin/env python3
import os
import sys

def verify_language(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    
    if len(lines) != 1629:
        print(f"[-] {filepath}: Invalid line count ({len(lines)}), expected 1629")
        return False

    english_name = lines[0]
    prefix_len = int(lines[2])
    words = lines[3:]

    prefixes = {}
    collisions = []

    for word in words:
        # Take the prefix in codepoints, case-folded for case-insensitive comparison
        prefix_cf = word[:prefix_len].casefold()
        if prefix_cf in prefixes:
            collisions.append((prefix_cf, prefixes[prefix_cf], word))
        else:
            prefixes[prefix_cf] = word

    if collisions:
        print(f"[-] {english_name} ({filepath}): Found {len(collisions)} CASE-INSENSITIVE collisions at prefix length {prefix_len}:")
        for pref, word1, word2 in collisions[:10]:
            print(f"    Prefix '{pref}' matches both '{word1}' and '{word2}'")
        if len(collisions) > 10:
            print(f"    ... and {len(collisions) - 10} more.")
        return False

    # Check if prefix_len is larger than necessary (case-insensitive)
    min_needed = 1
    while True:
        test_prefixes = set()
        collision_found = False
        for word in words:
            p = word[:min_needed].casefold()
            if p in test_prefixes:
                collision_found = True
                break
            test_prefixes.add(p)
        if not collision_found:
            break
        min_needed += 1
    
    if min_needed < prefix_len:
        print(f"[!] {english_name}: prefix_len is {prefix_len}, but {min_needed} would suffice (case-insensitive).")
    elif min_needed > prefix_len:
        print(f"[-] {english_name}: prefix_len {prefix_len} is INSUFFICIENT for case-insensitive uniqueness (needs {min_needed})")
        return False

    print(f"[+] {english_name}: Verified case-insensitive (prefix_len={prefix_len})")
    return True

def main():
    lang_dir = "src/mnemonics/languages"
    if not os.path.exists(lang_dir):
        print(f"Error: Directory {lang_dir} not found.")
        sys.exit(1)

    files = [f for f in os.listdir(lang_dir) if f.endswith('.txt')]
    files.sort()

    success = True
    for filename in files:
        if not verify_language(os.path.join(lang_dir, filename)):
            success = False
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
