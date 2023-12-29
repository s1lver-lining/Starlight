#!/usr/bin/env python3

"""
Utility file to replace references to links in a markdown file by the links themselves.
Used to convert content from CTF Katana.
"""

markdown_file = "README.md"
links = "links.txt"

dict_link_replace = {}
with open(links, "r") as f:
    links = f.read().splitlines()
    for link in links:
        repl_instance = link.split(": ")
        if len(repl_instance) < 2:
            print("Error: " + link)
        dict_link_replace[repl_instance[0]] = repl_instance[1]

# Replace links
with open(markdown_file, "r", encoding="utf-8") as f:
    text = f.read()
    for key, value in dict_link_replace.items():
        text = text.replace(key + key, key + "(" + value + ")")
        text = text.replace("]" + key, "](" + value + ")")
        text = text.replace(" " + key + " ", " " + key + "(" + value + ")" + " ")
        text = text.replace(" " + key + "\n", " " + key + "(" + value + ")" + " ")

with open("katana_linked.md", "w", encoding="utf-8") as f:
    f.write(text)
