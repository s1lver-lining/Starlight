#!/usr/bin/env python3

"""
Utility file to convert a png file to a dark mode version of itself.
Outputs the new image in the same directory with the name of the original file + "-dark.png"
"""

from PIL import Image
import sys
import argparse

def make_dark_mode_png(input_file, epsilon=0):
    image = Image.open(input_file, 'r')
    image = image.convert('RGBA')
    # Turn the black pixels into equivalent white pixels
    data = image.getdata()
    new_data = []
    for item in data:
        if item[0] <= epsilon and item[1] <= epsilon and item[2] <= epsilon:
            new_data.append((255, 255, 255, item[3]))
        else:
            new_data.append(item)
    image.putdata(new_data)
    newname = input_file.split('.')[0] + '-dark.png'
    image.save(newname)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="input file")
    parser.add_argument("-e", "--epsilon", help="epsilon value for black pixels", type=int, default=0)
    args = parser.parse_args()
    make_dark_mode_png(args.input_file, args.epsilon)