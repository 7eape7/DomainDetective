from art import art
import random

def tableflip():
    nums = ["","1","2", "3","4","5","6","7","8","9","10"]
    tf = f"table_flip{random.choice(nums)}"
    print
    print(f"\n{art(tf)}")

if __name__ == "__main__":
    tableflip()